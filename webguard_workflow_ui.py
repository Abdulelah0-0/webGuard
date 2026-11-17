"""Dialogs for remediation ownership and incident notes."""
import tkinter as tk
from tkinter import messagebox, ttk

from webguard_workflow import INCIDENT_FIELDS, STATUSES, finding_rows, update_finding, update_incident

BG = "#0C111D"
FG = "#E8EDF6"
AR_STATUS = {"review": "تحتاج تحقق", "open": "مفتوحة", "working": "قيد الإصلاح",
             "verify": "جاهزة للتحقق", "verified": "تم التحقق من الإصلاح"}
AR_INCIDENT = {
    "observed_at": "وقت الرصد أو الفترة",
    "affected_assets": "الأصول المتأثرة",
    "log_references": "مراجع السجلات والأدلة",
    "containment_taken": "إجراءات الاحتواء المتخذة",
    "open_questions": "الأسئلة المفتوحة",
}


def _label(parent, title):
    return tk.Label(parent, text=title, bg=BG, fg=FG, anchor="w")


def _dialog(panel, ar, en, size):
    window = tk.Toplevel(panel.window, bg=BG)
    window.title(panel.label(ar, en))
    window.geometry(size)
    window.transient(panel.window)
    outer = tk.Frame(window, bg=BG, padx=16, pady=12)
    outer.pack(fill="both", expand=True)
    return window, outer


def _text(parent, height, wrap="word"):
    return tk.Text(parent, height=height, wrap=wrap, bg="#142035", fg=FG,
                   insertbackground=FG, relief="flat", padx=8, pady=5)


def show_tracking(panel):
    window, outer = _dialog(panel, "متابعة النتائج", "Finding tracking", "950x680")
    window.minsize(790, 580)
    arabic = not panel.app.english
    statuses = AR_STATUS if arabic else STATUSES
    keys_by_label = {value: key for key, value in statuses.items()}
    table_frame = tk.Frame(outer, bg=BG)
    table_frame.pack(fill="both", expand=True)
    table = ttk.Treeview(table_frame, columns=("title", "status", "owner"), show="headings",
                         selectmode="browse", height=5)
    for key, ar, en, width in (
        ("title", "الملاحظة والأصل", "Finding and asset", 520),
        ("status", "الحالة", "Status", 170),
        ("owner", "المسؤول", "Owner", 135),
    ):
        table.heading(key, text=panel.label(ar, en), anchor="w")
        table.column(key, width=width, stretch=key == "title")
    table.pack(side="left", fill="both", expand=True)
    scroll = ttk.Scrollbar(table_frame, command=table.yview)
    scroll.pack(side="right", fill="y")
    table.configure(yscrollcommand=scroll.set)
    _label(outer, panel.label("مصادر الدليل والسجل", "Evidence sources and history")).pack(fill="x", pady=(8, 3))
    details = _text(outer, 6)
    details.pack(fill="x")
    details.configure(state="disabled")
    fields = tk.Frame(outer, bg=BG)
    fields.pack(fill="x", pady=8)
    _label(fields, panel.label("المسؤول", "Owner")).pack(side="left")
    owner = tk.StringVar(master=window)
    ttk.Entry(fields, textvariable=owner, width=25).pack(side="left", padx=(6, 14))
    _label(fields, panel.label("الحالة", "Status")).pack(side="left")
    status = tk.StringVar(master=window)
    ttk.Combobox(fields, textvariable=status, values=list(statuses.values()),
                 state="readonly", width=24).pack(side="left", padx=6)
    _label(outer, panel.label("ملاحظة أو دليل التحقق", "Note or verification evidence")).pack(fill="x")
    note = _text(outer, 3)
    note.pack(fill="x", pady=4)
    rows = {}

    def populate(select=None):
        rows.clear()
        table.delete(*table.get_children())
        for row in finding_rows(panel.workspace):
            rows[row["key"]] = row
            table.insert("", "end", iid=row["key"],
                         values=(f"{row['title']}  |  {row['asset']}", statuses[row["status"]], row["owner"]))
        if select in rows:
            table.selection_set(select)
        elif rows:
            table.selection_set(next(iter(rows)))

    def show(_event=None):
        selection = table.selection()
        if not selection or selection[0] not in rows:
            return
        row = rows[selection[0]]
        owner.set(row["owner"])
        status.set(statuses[row["status"]])
        note.delete("1.0", "end")
        lines = []
        if not row["current"]:
            lines.append(panel.label("دليل محفوظ من فحص سابق.", "Retained evidence from an earlier observation."))
        elif row["recheck"]:
            lines.append(panel.label("تغيّر الدليل المطابق بعد التحقق.",
                                     "Matching evidence changed after verification."))
        lines.extend(f"{item['source']} / {item['id']} / {item['observed_at']}\n{item['text']}"
                     for item in row["evidence"])
        lines.extend(f"{event['at']} | {statuses[event['status']]} | {event['owner']} | {event['note']}"
                     for event in row["history"])
        details.configure(state="normal")
        details.delete("1.0", "end")
        details.insert("1.0", "\n\n".join(lines))
        details.configure(state="disabled")

    def save():
        selection = table.selection()
        if not selection:
            return
        try:
            update_finding(panel.workspace, selection[0], keys_by_label[status.get()],
                           owner.get(), note.get("1.0", "end-1c"))
        except (ValueError, KeyError) as error:
            messagebox.showerror(panel.label("تعذّر الحفظ", "Could not save"), str(error), parent=window)
            return
        populate(selection[0])
        panel.refresh()

    table.bind("<<TreeviewSelect>>", show)
    ttk.Button(outer, text=panel.label("حفظ تحديث النتيجة", "Save finding update"),
               style="Primary.TButton", command=save).pack(anchor="w", pady=(8, 0))
    populate()
    show()


def show_incident(panel):
    window, outer = _dialog(panel, "ملاحظات الاستجابة للحادث", "Incident response notes", "800x670")
    window.minsize(700, 625)
    fields = {}
    for key, name in INCIDENT_FIELDS.items():
        _label(outer, panel.label(AR_INCIDENT[key], name)).pack(fill="x", pady=(6, 2))
        widget = fields[key] = _text(outer, 2 if key == "observed_at" else 3)
        widget.pack(fill="both", expand=True)
        widget.insert("1.0", panel.workspace.get("incident", {}).get(key, ""))

    def save():
        try:
            update_incident(panel.workspace, {key: field.get("1.0", "end-1c") for key, field in fields.items()})
        except ValueError as error:
            messagebox.showerror(panel.label("تعذّر الحفظ", "Could not save"), str(error), parent=window)
        else:
            window.destroy()

    ttk.Button(outer, text=panel.label("حفظ ملاحظات الحادث", "Save incident notes"),
               command=save, style="Primary.TButton").pack(anchor="w", pady=(10, 0))
