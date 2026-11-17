"""Desktop views for the local scan log and HTTP evidence."""
import json
import sqlite3
import tkinter as tk
from tkinter import messagebox, ttk

from webguard_history import compare_scans, history_path, read_scan, recent_scans


def show_text(app, title, content):
    window = tk.Toplevel(app.root, bg="#0C111D")
    window.title(title)
    window.geometry("850x540")
    pane = tk.Text(window, wrap="word", padx=16, pady=14,
                   bg="#141E30", fg="#E8EDF6", relief="flat")
    pane.pack(side="left", fill="both", expand=True)
    scroll = ttk.Scrollbar(window, command=pane.yview)
    scroll.pack(side="right", fill="y")
    pane.configure(yscrollcommand=scroll.set)
    pane.insert("1.0", content)
    pane.configure(state="disabled")


def show_http(app):
    report = app.report
    if not report:
        return
    score = report.get("configuration_score")
    parts = [f"GET {report['url']}", f"HTTP {report['status']}", "",
             app.tr("دليل HTTP المنقّح"),
             json.dumps(report.get("http", {}), indent=2, ensure_ascii=False)]
    coverage = report.get("control_coverage", {})
    if coverage:
        parts.extend(["", app.tr("تغطية الفحص")])
        parts.extend(f"{check}: {state}" for check, state in coverage.items())
    if score:
        parts.extend(["", f"{app.tr('درجة الإعدادات الأمنية')}  {score['value']}/100",
                      app.tr("الدرجة تخص الضوابط المقاسة في هذه الاستجابة.")])
        for check in score["checks"]:
            reasons = ", ".join(check["reasons"])
            parts.append(f"{check['name']}  {check['earned']}/{check['weight']}  {reasons}")
    show_text(app, app.tr("دليل HTTP المنقّح"), "\n".join(parts))


def show_history(app):
    path = history_path()
    title = app.tr("سجل الفحوصات")
    try:
        rows = recent_scans(path)
    except (OSError, sqlite3.Error):
        messagebox.showerror(title, app.tr("تعذّر الوصول إلى السجل المحلي."), parent=app.root)
        return
    window = tk.Toplevel(app.root, bg="#0C111D")
    window.title(title)
    window.geometry("970x490")
    footer = ttk.Frame(window, padding=10)
    footer.pack(side="bottom", fill="x")
    table = ttk.Treeview(window, columns=("url", "date", "count"), show="headings", selectmode="extended")
    for key, label, width in (("url", "رابط الصفحة", 545), ("date", "وقت الرصد", 240), ("count", "الملاحظة", 100)):
        table.heading(key, text=app.tr(label))
        table.column(key, width=width)
    for scan_id, target, observed, count in rows:
        table.insert("", "end", iid=str(scan_id), values=(target, observed, count))
    table.pack(side="left", fill="both", expand=True)
    scroll = ttk.Scrollbar(window, command=table.yview)
    scroll.pack(side="right", fill="y")
    table.configure(yscrollcommand=scroll.set)

    def action(compare=False):
        chosen = sorted(map(int, table.selection()))
        if len(chosen) != (2 if compare else 1) or app.cancel:
            return
        try:
            reports = [read_scan(path, item) for item in chosen]
            if compare:
                result = compare_scans(*reports)
                summary = app.tr("يحتاج تغيّر النتائج إلى تحقق قبل الإغلاق.")
                if not result["comparable"]:
                    summary += "\n" + app.tr("تغطية الاستجابتين مختلفة.")
                changed = set(result["changed_evidence"])
                marker = app.tr("تغيّر الدليل")
                if result["comparable"]:
                    lines = [f"{name}: {old} → {new}" + (f"  |  {marker}" if name in changed else "")
                             for name, old, new in result["rows"]]
                else:
                    lines = [f"{name}: {old} / {new}" for name, old, new in result["rows"]]
                show_text(app, app.tr("مقارنة الفحوصات"), "\n".join([summary, "", *lines]))
            else:
                app.filter.set(app.tr("الكل"))
                app.show_report(reports[0])
                app.set_busy(False)
                window.destroy()
        except (OSError, sqlite3.Error, ValueError):
            messagebox.showerror(title, app.tr("تعذّرت العملية. للمقارنة اختر نتيجتين لنفس الرابط الظاهر."),
                                 parent=window)

    ttk.Button(footer, text=app.tr("فتح النتيجة"), command=action).pack(side="left")
    ttk.Button(footer, text=app.tr("مقارنة نتيجتين"), command=lambda: action(True)).pack(side="left", padx=8)
