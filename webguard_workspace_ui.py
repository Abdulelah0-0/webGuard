"""Workspace panel for scope, imported evidence, and PDF export."""
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk

from webguard_source_review import review_source
from webguard_imports import import_report
from webguard_workflow_ui import show_incident, show_tracking
from webguard_workspace import (
    compare_workspaces, load_workspace, new_workspace,
    record_scan, register_asset, save_workspace, workspace_report,
)


class WorkspacePanel:
    def __init__(self, app):
        self.app = app
        self.window = tk.Toplevel(app.root, bg="#0C111D")
        self.window.title(self.label("مساحة عمل التدقيق", "Assessment workspace"))
        self.window.geometry("910x560")
        self.window.minsize(850, 480)
        self.window.transient(app.root)
        self.window.protocol("WM_DELETE_WINDOW", self.close)
        self.summary = tk.StringVar(master=self.window)
        outer = tk.Frame(self.window, bg="#0C111D", padx=18, pady=15)
        outer.pack(fill="both", expand=True)
        tk.Label(outer, textvariable=self.summary, bg="#0C111D", fg="#E8EDF6",
                 justify="left" if app.english else "right",
                 anchor="w" if app.english else "e", font=("Segoe UI", 11, "bold")).pack(fill="x", pady=(0, 12))
        toolbar = tk.Frame(outer, bg="#0C111D")
        toolbar.pack(fill="x")
        for arabic, english, handler in (
            ("تسجيل أصل", "Register asset", self.register),
            ("إضافة آخر فحص", "Add latest scan", self.capture),
            ("استيراد نتائج", "Import findings", self.import_file),
            ("مراجعة Python", "Review Python", self.review),
            ("اختيار تقرير أساس", "Select baseline", self.choose_baseline),
        ):
            ttk.Button(toolbar, text=self.label(arabic, english), command=handler).pack(side="left", padx=(0, 6))

        actions = tk.Frame(outer, bg="#0C111D")
        actions.pack(fill="x", pady=(7, 0))
        ttk.Button(actions, text=self.label("متابعة النتائج", "Finding tracking"),
                   command=lambda: show_tracking(self)).pack(side="left", padx=(0, 6))
        ttk.Button(actions, text=self.label("ملاحظات الحادث", "Incident notes"),
                   command=lambda: show_incident(self)).pack(side="left")

        footer = tk.Frame(outer, bg="#0C111D")
        footer.pack(side="bottom", fill="x", pady=(12, 0))
        for arabic, english, handler in (
            ("فتح مساحة", "Open workspace", self.open),
            ("حفظ مساحة", "Save workspace", self.save),
            ("تصدير PDF إنجليزي", "Export English PDF", self.export),
        ):
            ttk.Button(footer, text=self.label(arabic, english), command=handler,
                       style="Primary.TButton" if handler == self.export else "TButton").pack(side="left", padx=(0, 6))
        grid = tk.Frame(outer, bg="#0C111D")
        grid.pack(fill="both", expand=True, pady=(10, 0))
        self.table = ttk.Treeview(grid, columns=("asset", "coverage", "count"), show="headings")
        for key, title, width, anchor in (
            ("asset", self.label("الأصل", "Asset"), 340, "w"),
            ("coverage", self.label("التغطية", "Coverage"), 245, "w"),
            ("count", self.label("الملاحظات", "Findings"), 85, "center"),
        ):
            self.table.heading(key, text=title)
            self.table.column(key, width=width, anchor=anchor, stretch=key == "asset")
        self.table.pack(side="left", fill="both", expand=True)
        scrollbar = ttk.Scrollbar(grid, command=self.table.yview)
        scrollbar.pack(side="right", fill="y")
        self.table.configure(yscrollcommand=scrollbar.set)
        self.refresh()

    def label(self, ar, en):
        return en if self.app.english else ar

    @property
    def workspace(self):
        return self.app.workspace

    def close(self):
        self.app.workspace_panel = None
        self.window.destroy()

    def refresh(self):
        self.table.delete(*self.table.get_children())
        for asset, scan in sorted(self.workspace["assets"].items()):
            imported = sum(item["asset"] == asset for item in self.workspace["external"].values())
            coverage = (f"HTTP {scan['status']} | {scan['checked_at'][:10]}" if scan else
                        self.label("بانتظار فحص WebGuard", "No WebGuard observation"))
            self.table.insert("", "end", values=(asset, coverage,
                              imported + (len(scan["findings"]) if scan else 0)))
        assets, findings = len(self.workspace["assets"]), len(self.workspace["external"])
        status = self.label(f"{assets} أصل  |  {findings} نتيجة مستوردة",
                            f"{assets} assets  |  {findings} imported findings")
        if self.app.workspace_baseline is not None:
            changes = len(compare_workspaces(self.workspace, self.app.workspace_baseline))
            status += self.label(f"  |  المقارنة تشمل {changes} بندًا", f"  |  {changes} comparison entries")
        self.summary.set(status)

    def run(self, action):
        try:
            action()
        except (OSError, ValueError, TypeError, KeyError, ImportError) as error:
            messagebox.showerror(self.label("تعذّر تنفيذ العملية", "Operation failed"),
                                 str(error), parent=self.window)
        else:
            self.refresh()

    def register(self):
        value = simpledialog.askstring(
            self.label("تسجيل أصل", "Register asset"),
            self.label("أدخل رابط أصل مصرّح بتدقيقه. احذف المسارات الحساسة.",
                       "Enter an authorized asset URL. Remove any sensitive paths."),
            parent=self.window,
        )
        if value:
            self.run(lambda: register_asset(self.workspace, value))

    def capture(self):
        if self.app.report is None:
            messagebox.showinfo(self.label("إضافة فحص", "Add scan"),
                                self.label("أكمل فحصًا في النافذة الرئيسية أولًا.",
                                           "Complete a scan in the main window first."), parent=self.window)
        else:
            self.run(lambda: record_scan(self.workspace, self.app.report))

    def json_path(self, save=False, **options):
        dialog = filedialog.asksaveasfilename if save else filedialog.askopenfilename
        return dialog(parent=self.window, filetypes=[("JSON", "*.json")], defaultextension=".json", **options)

    def import_file(self):
        path = filedialog.askopenfilename(
            parent=self.window, filetypes=[("Findings (JSON, CSV, SARIF)", "*.json *.csv *.sarif")])
        if path:
            selection = self.table.selection()
            asset = self.table.item(selection[0], "values")[0] if selection else None
            def import_selected():
                count = import_report(self.workspace, path, asset)
                messagebox.showinfo(self.label("استيراد النتائج", "Import findings"),
                                    self.label(f"تمت معالجة {count} نتيجة.", f"Processed {count} finding(s)."),
                                    parent=self.window)
            self.run(import_selected)

    def review(self):
        selection = self.table.selection()
        if not selection:
            messagebox.showinfo(self.label("مراجعة المصدر", "Source review"),
                                self.label("حدد الأصل من الجدول أولًا.", "Select an asset first."),
                                parent=self.window)
            return
        asset = self.table.item(selection[0], "values")[0]
        path = filedialog.askopenfilename(parent=self.window, filetypes=[("Python", "*.py")])
        if path:
            def analyze():
                count = review_source(self.workspace, asset, path)
                messagebox.showinfo(self.label("مراجعة المصدر", "Source review"),
                                    self.label(f"{count} مؤشر يحتاج مراجعة.",
                                               f"{count} indicator(s) require review."), parent=self.window)
            self.run(analyze)

    def choose_baseline(self):
        path = self.json_path()
        if path:
            self.run(lambda: setattr(self.app, "workspace_baseline", load_workspace(path)))

    def open(self):
        path = self.json_path()
        if not path:
            return
        if (self.workspace["assets"] or self.workspace["external"]) and not messagebox.askyesno(
            self.label("استبدال المساحة الحالية", "Replace current workspace"),
            self.label("سيُستبدل ما في الذاكرة بالملف المختار. هل حفظت التغييرات المطلوبة؟",
                       "The selected file will replace the workspace in memory. Continue?"), parent=self.window,
        ):
            return
        def replace():
            self.app.workspace = load_workspace(path)
            self.app.workspace_baseline = None
        self.run(replace)

    def save(self):
        path = self.json_path(save=True, initialfile="WebGuard_Workspace.json")
        if path:
            self.run(lambda: save_workspace(self.workspace, path))

    def export(self):
        path = filedialog.asksaveasfilename(parent=self.window, defaultextension=".pdf",
                                             filetypes=[("PDF", "*.pdf")],
                                             initialfile="WebGuard_Assessment.pdf")
        if path:
            self.run(lambda: workspace_report(self.workspace, Path(path), self.app.workspace_baseline))
