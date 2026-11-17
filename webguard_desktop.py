"""WebGuard Windows desktop application."""
from __future__ import annotations

import ctypes
import json
import sys
import multiprocessing as mp
import queue
import sqlite3
import threading
import tkinter as tk
from collections import Counter
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog, ttk

from webguard import SEVERITY_AR, SEVERITY_ORDER, VERSION, normalize_url, public_url, scan
from webguard_inventory import batch_rows, import_inventory
from xml.etree.ElementTree import ParseError
from webguard_openapi import inspect_spec
from webguard_audit_ui import show_history, show_http, show_text
from webguard_history import history_path, save_scan
from webguard_scope import audit_urls, discover_saved_html, scope_urls
from webguard_workspace import record_scan, register_asset
from webguard_english import ERRORS, HTML_STATUS_EN, RESPONSE_EN, SEVERITY_EN, english_finding
from webguard_pdf import pdf_report
from webguard_reports import HTML_STATUS, html_report
from webguard_workspace import new_workspace
from webguard_workspace_ui import WorkspacePanel

NAVY = "#E8EDF6"
SLATE = "#A5B2C9"
BG = "#0C111D"
WHITE = "#141E30"
ACCENT = "#2259A8"
BORDER = "#2B3B55"
HEADER = "#10192A"
DETAIL = "#101827"
HOVER = "#263B5B"
FONT = "Segoe UI"
COLORS = {"high": "#FF9AA7", "medium": "#F5C87A", "low": "#8FC0FF", "info": "#A5B2C9"}

EN = {
    "تغطية الفحص": "Assessment coverage",
    "تغيّر الدليل": "Evidence changed",
    "روابط من HTML": "Links from HTML",
    "روابط داخلية مقترحة": "Suggested internal URLs",
    "تعذّرت قراءة صفحة HTML المحلية.": "Could not read the saved HTML page.",
    "سجل الفحوصات": "Scan history",
    "دليل HTTP المنقّح": "Redacted HTTP evidence",
    "درجة الإعدادات الأمنية": "Security configuration score",
    "الدرجة تخص الضوابط المقاسة في هذه الاستجابة.": "Score applies to the controls evaluated in this response.",
    "وقت الرصد": "Observed at",
    "فتح النتيجة": "Open result",
    "مقارنة نتيجتين": "Compare two selected scans",
    "مقارنة الفحوصات": "Compare scans",
    "يحتاج تغيّر النتائج إلى تحقق قبل الإغلاق.": "Verify changes before closing findings.",
    "تغطية الاستجابتين مختلفة.": "Response coverage differs.",
    "تعذّر الوصول إلى السجل المحلي.": "Could not access local scan history.",
    "تعذّرت العملية. للمقارنة اختر نتيجتين لنفس الرابط الظاهر.": "Operation failed. Compare two scans of the same unredacted, query-free URL.",
    "تدقيق قائمة روابط": "Audit a URL list",
    "أدخل روابط مصرّح بها من نفس الأصل، مفصولة بفواصل. تُحفظ المسارات في مساحة العمل والسجل.": "Enter authorized same-origin URLs separated by commas. Paths are retained in the workspace and history.",
    "مؤشر يحتاج مراجعة": "Response-based indicator",
    "الرابط المتأثر": "Affected URL",
    "الثقة": "Confidence",

    "مساحة التدقيق": "Workspace",
    "تدقيق أمان الويب": "Web Security",
    "تدقيق إعدادات أمان الويب": "Web security assessment",
    "رابط الصفحة": "Target URL",
    "بدء التدقيق": "Run assessment",
    "إلغاء": "Cancel",
    "لدي صلاحية لفحص هذا الموقع": "I am authorized to assess this site",
    "إخفاء المسار في التقرير": "Hide URL path in reports",
    "المهلة بالثواني": "Timeout (seconds)",
    "نتائج التدقيق": "Assessment findings",
    "الخطورة": "Severity",
    "الكل": "All",
    "الملاحظة": "Finding",
    "المعرّف": "Check ID",
    "الدليل والإجراء المقترح": "Evidence and remediation",
    "نسخ الملاحظة": "Copy finding",
    "اختر ملاحظة لعرض دليلها وتوصية الإصلاح.": "Select a finding to review its evidence and remediation.",
    "جاهز للفحص": "Ready",
    "أدخل رابط الصفحة لعرض نتائج التدقيق.": "Enter a URL to begin.",
    "صلاحية الفحص": "Assessment authorization",
    "أكد أن لديك صلاحية لفحص هذا الموقع.": "Confirm that you are authorized to assess this site.",
    "راجع المدخلات": "Check the input",
    "مهلة غير صالحة": "Invalid timeout",
    "اختر مهلة من 1 إلى 60 ثانية.": "Choose a timeout from 1 to 60 seconds.",
    "جارٍ الاتصال بالصفحة…": "Connecting to the page…",
    "حدث خطأ داخلي أثناء تشغيل التدقيق.": "An internal error occurred during assessment.",
    "جارٍ إلغاء الفحص…": "Cancelling the assessment…",
    "أُلغي الفحص": "Assessment cancelled",
    "يمكنك بدء فحص جديد.": "You can start a new assessment.",
    "تعذّر إكمال الفحص": "Assessment could not be completed",
    "لا توجد ملاحظات ضمن العرض الحالي.": "No findings match the current view.",
    "نُسخت الملاحظة": "Finding copied",
    "حفظ تقرير WebGuard": "Save WebGuard report",
    "تعذّر الحفظ": "Could not save the report",
    "تعذّر كتابة التقرير في المسار المحدد.": "The report could not be written to the selected path.",
    "تصدير PDF (إنجليزي)": "Export PDF (English)",
    "تحتاج إلى تثبيت اعتماديات التقارير من requirements-report.txt.": "Install the report dependencies from requirements-report.txt.",
}


class WebGuardApp:
    def __init__(self, root):
        self.root = root
        self.language = tk.StringVar(master=root, value="العربية")
        root.geometry("1180x820")
        root.minsize(950, 720)
        root.configure(bg=BG)
        root.option_add("*Font", f"{{{FONT}}} 10")
        self.url = tk.StringVar()
        self.timeout = tk.StringVar(value="8")
        self.hide_path = tk.BooleanVar(value=True)
        self.authorized = tk.BooleanVar()
        self.filter = tk.StringVar(value="الكل")
        self.status = tk.StringVar(value=self.tr("جاهز للفحص"))
        self.coverage = tk.StringVar(value=self.tr("أدخل رابط الصفحة لعرض نتائج التدقيق."))
        self.report = None
        self.workspace = new_workspace()
        self.workspace_baseline = None
        self.workspace_panel = None
        self.cancel = None
        self.messages = queue.Queue()
        self.closing = False
        self.build()
        root.protocol("WM_DELETE_WINDOW", self.close)

    @property
    def english(self):
        return self.language.get() == "English"

    def tr(self, text):
        return EN.get(text, text) if self.english else text

    def switch_language(self, _event=None):
        if self.cancel is not None:
            return
        levels = {label: key for names in (SEVERITY_AR, SEVERITY_EN) for key, label in names.items()}
        selected_level = levels.get(self.filter.get())
        self.filter.set(self.severity_names.get(selected_level, self.tr("الكل")))
        if self.workspace_panel:
            self.workspace_panel.close()
        for widget in self.root.winfo_children():
            widget.destroy()
        self.build()
        if self.report:
            self.show_report(self.report)
            self.set_busy(False)
        else:
            self.coverage.set(self.tr("أدخل رابط الصفحة لعرض نتائج التدقيق."))
            self.status.set(self.tr("جاهز للفحص"))

    @property
    def severity_names(self):
        return SEVERITY_EN if self.english else SEVERITY_AR

    def build(self):
        self.root.title(f"WebGuard {VERSION} | {self.tr('تدقيق أمان الويب')}")
        style = ttk.Style(self.root)
        style.theme_use("clam")
        style.configure(".", background=BG, foreground=NAVY, bordercolor=BORDER,
                        darkcolor=DETAIL, lightcolor=WHITE, fieldbackground=DETAIL,
                        troughcolor=DETAIL, selectbackground=HOVER, selectforeground=NAVY,
                        insertcolor=NAVY, arrowcolor=SLATE)
        style.configure("TButton", padding=(12, 7), background=WHITE, foreground=NAVY)
        style.map("TButton", background=[("active", HOVER)], foreground=[("disabled", SLATE)])
        style.map("TCombobox", fieldbackground=[("readonly", DETAIL)],
                  foreground=[("readonly", NAVY)], selectbackground=[("readonly", DETAIL)])
        style.configure("Vertical.TScrollbar", background=HOVER)
        style.configure("Horizontal.TProgressbar", background="#70AAFF")
        self.root.option_add("*TCombobox*Listbox.background", DETAIL)
        self.root.option_add("*TCombobox*Listbox.foreground", NAVY)
        self.root.option_add("*TCombobox*Listbox.selectBackground", HOVER)
        style.configure("Compact.TButton", padding=(10, 4), background=WHITE, foreground=NAVY)
        style.configure("Primary.TButton", background=ACCENT, foreground="#FFFFFF",
                        bordercolor=ACCENT, font=(FONT, 10, "bold"))
        style.map("Primary.TButton", background=[("disabled", "#25344A"), ("active", "#2D6CC3")],
                  foreground=[("disabled", SLATE)])
        style.configure("Treeview", rowheight=31, background=WHITE, fieldbackground=WHITE,
                        foreground=NAVY, borderwidth=0)
        style.configure("Treeview.Heading", background="#1E2C44", foreground=NAVY,
                        relief="flat", padding=(8, 8), font=(FONT, 10, "bold"))
        style.map("Treeview", background=[("selected", HOVER)],
                  foreground=[("selected", NAVY)])
        style.configure("Card.TCheckbutton", background=WHITE, foreground=NAVY)
        style.map("Card.TCheckbutton", background=[("active", WHITE)])

        header = tk.Frame(self.root, bg=HEADER, padx=26, pady=10)
        header.pack(fill="x")
        brand = tk.Frame(header, bg=HEADER)
        brand.pack(side="left")
        mark = tk.Canvas(brand, width=34, height=38, bg=HEADER, highlightthickness=0)
        mark.pack(side="left", padx=(0, 10))
        mark.create_polygon(17, 2, 31, 8, 29, 24, 17, 35, 5, 24, 3, 8,
                            fill=ACCENT, outline="#77AAFA", width=1)
        mark.create_line(11, 18, 16, 23, 23, 13, fill="#FFFFFF", width=2,
                         capstyle="round", joinstyle="round")
        words = tk.Frame(brand, bg=HEADER)
        words.pack(side="left")
        self.label(words, "WebGuard", 18, NAVY, HEADER, True).pack(anchor="w")
        self.label(words, "تدقيق إعدادات أمان الويب", 9, SLATE, HEADER).pack(anchor="w")
        self.language_box = ttk.Combobox(header, textvariable=self.language,
                                         values=("العربية", "English"), state="readonly",
                                         width=12, justify="center")
        self.language_box.pack(side="right")
        self.language_box.bind("<<ComboboxSelected>>", self.switch_language)
        self.label(header, f"v{VERSION}", 10, SLATE, HEADER).pack(side="right", padx=14)
        ttk.Button(header, text=self.tr("مساحة التدقيق"), command=self.open_workspace).pack(side="right")
        ttk.Button(header, text=self.tr("سجل الفحوصات"),
                   command=lambda: show_history(self)).pack(side="right", padx=6)
        tk.Frame(self.root, bg=BORDER, height=1).pack(fill="x")

        shell = tk.Frame(self.root, bg=BG, padx=24, pady=12)
        shell.pack(fill="both", expand=True)
        target = self.card(shell, 15, 8)
        target.pack(fill="x")
        target.columnconfigure(0, weight=1)
        self.label(target, "رابط الصفحة", bold=True).grid(row=0, column=0, sticky="w" if self.english else "e")
        self.url_entry = ttk.Entry(target, textvariable=self.url, font=(FONT, 11))
        self.url_entry.grid(row=1, column=0, sticky="ew", ipady=5, padx=(0, 12), pady=(3, 5))
        self.url_entry.bind("<Return>", lambda _: self.start())
        self.start_button = ttk.Button(target, text=self.tr("بدء التدقيق"), style="Primary.TButton", command=self.start)
        self.start_button.grid(row=1, column=1)
        self.cancel_button = ttk.Button(target, text=self.tr("إلغاء"), command=self.cancel_scan, state="disabled")
        self.cancel_button.grid(row=1, column=2, padx=(8, 0))
        options = tk.Frame(target, bg=WHITE)
        options.grid(row=2, column=0, columnspan=3, sticky="ew")
        self.permission = ttk.Checkbutton(options, text=self.tr("لدي صلاحية لفحص هذا الموقع"),
                                           variable=self.authorized, style="Card.TCheckbutton")
        self.permission.pack(side="right")
        self.privacy = ttk.Checkbutton(options, text=self.tr("إخفاء المسار في التقرير"),
                                        variable=self.hide_path, style="Card.TCheckbutton")
        self.privacy.pack(side="right", padx=18)
        self.label(options, "المهلة بالثواني", fg=SLATE).pack(side="left")
        self.timeout_entry = ttk.Spinbox(options, from_=1, to=60, width=5, textvariable=self.timeout)
        self.timeout_entry.pack(side="left", padx=8)
        self.standard_button = ttk.Button(options, text=self.tr("تدقيق قائمة روابط"),
                                         style="Compact.TButton", command=lambda: self.start(standard=True))
        self.standard_button.pack(side="left", padx=4)
        self.inventory_button = ttk.Button(options, text=self.tr("روابط من HTML"),
                                           style="Compact.TButton", command=self.discover_links)
        self.inventory_button.pack(side="left")

        summary = tk.Frame(shell, bg=BG)
        summary.pack(fill="x", pady=8)
        self.counts = {}
        order = SEVERITY_ORDER if self.english else reversed(SEVERITY_ORDER)
        for column, level in enumerate(order):
            summary.columnconfigure(column, weight=1, uniform="severity")
            card = self.card(summary, 13, 4)
            card.grid(row=0, column=column, sticky="ew", padx=(0 if not column else 5, 0))
            tk.Frame(card, bg=COLORS[level], width=3).pack(side="left", fill="y", padx=(0, 10))
            self.label(card, self.severity_names[level], fg=COLORS[level], bold=True).pack(side="left")
            self.counts[level] = self.label(card, "—", 17, NAVY, WHITE, True)
            self.counts[level].pack(side="right")

        footer = tk.Frame(shell, bg=BG)
        footer.pack(side="bottom", fill="x", pady=(10, 0))
        self.export_buttons = []
        for fmt in ("PDF", "HTML", "JSON"):
            label = (self.tr("تصدير PDF (إنجليزي)") if fmt == "PDF" else
                     f"Save {fmt}" if self.english else f"حفظ {fmt}")
            button = ttk.Button(footer, text=label, state="disabled",
                                style="Primary.TButton" if fmt == "PDF" else "TButton",
                                command=lambda format_name=fmt: self.export(format_name))
            button.pack(side="left", padx=(0, 6))
            self.export_buttons.append(button)
        self.http_button = ttk.Button(footer, text="HTTP", command=lambda: show_http(self), state="disabled")
        self.http_button.pack(side="left", padx=(0, 6))
        self.spec_button = ttk.Button(footer, text="Sitemap / OpenAPI", command=self.import_url_inventory)
        self.spec_button.pack(side="left", padx=(0, 6))
        ttk.Button(footer, text="OpenAPI", command=self.open_api_spec).pack(side="left", padx=(0, 6))
        self.progress = ttk.Progressbar(footer, mode="indeterminate", length=75)
        tk.Label(footer, textvariable=self.status, bg=BG, fg=SLATE).pack(side="right")

        result = self.card(shell, 14, 8)
        result.pack(fill="both", expand=True)
        toolbar = tk.Frame(result, bg=WHITE)
        toolbar.pack(fill="x")
        reading_side = "left" if self.english else "right"
        control_side = "right" if self.english else "left"
        self.label(toolbar, "نتائج التدقيق", 13, bold=True).pack(side=reading_side)
        self.filter_box = ttk.Combobox(toolbar, textvariable=self.filter, width=12, state="readonly",
                                      values=(self.tr("الكل"), *self.severity_names.values()),
                                      justify="left" if self.english else "right")
        self.filter_box.pack(side=control_side)
        self.filter_box.bind("<<ComboboxSelected>>", lambda _: self.render_findings())
        self.label(toolbar, "الخطورة", fg=SLATE).pack(side=control_side, padx=8)
        tk.Label(result, textvariable=self.coverage, bg=WHITE, fg=SLATE,
                 anchor="w" if self.english else "e",
                 justify="left" if self.english else "right", wraplength=840).pack(fill="x", pady=(6, 7))

        detail = tk.Frame(result, bg=DETAIL)
        detail.pack(side="bottom", fill="x")
        self.details = tk.Text(detail, height=3, wrap="word", relief="flat", bg=DETAIL,
                               fg=NAVY, padx=12, pady=5, font=(FONT, 10))
        self.details.tag_configure("alignment", justify="left" if self.english else "right")
        self.details.pack(side="left", fill="x", expand=True)
        detail_scroll = ttk.Scrollbar(detail, command=self.details.yview)
        detail_scroll.pack(side="right", fill="y")
        self.details.configure(yscrollcommand=detail_scroll.set)
        self.set_details("اختر ملاحظة لعرض دليلها وتوصية الإصلاح.")

        detail_bar = tk.Frame(result, bg=WHITE)
        detail_bar.pack(side="bottom", fill="x", pady=(7, 3))
        self.label(detail_bar, "الدليل والإجراء المقترح", bold=True).pack(side=reading_side)
        self.copy_button = ttk.Button(detail_bar, text=self.tr("نسخ الملاحظة"), style="Compact.TButton", command=self.copy, state="disabled")
        self.copy_button.pack(side=control_side)
        grid = tk.Frame(result, bg=WHITE)
        grid.pack(fill="both", expand=True)
        self.table = ttk.Treeview(grid, columns=("description", "id", "severity"),
                                  show="headings", selectmode="browse", height=5)
        for key, title, width, anchor in (
            ("description", "الملاحظة", 540, "e"),
            ("id", "المعرّف", 238, "w"),
            ("severity", "الخطورة", 83, "center"),
        ):
            anchor = "w" if key == "description" and self.english else anchor
            self.table.heading(key, text=self.tr(title), anchor=anchor)
            self.table.column(key, width=width, anchor=anchor, stretch=key == "description")
        self.table.pack(side="left", fill="both", expand=True)
        scrollbar = ttk.Scrollbar(grid, orient="vertical", command=self.table.yview)
        scrollbar.pack(side="right", fill="y")
        self.table.configure(yscrollcommand=scrollbar.set)
        for level, color in COLORS.items():
            self.table.tag_configure(level, foreground=color)
        self.table.bind("<<TreeviewSelect>>", lambda _: self.show_selection())

        self.url_entry.focus_set()

    def label(self, parent, text, size=10, fg=NAVY, bg=WHITE, bold=False):
        return tk.Label(parent, text=self.tr(text), bg=bg, fg=fg, font=(FONT, size, "bold" if bold else "normal"))

    @staticmethod
    def card(parent, padx, pady):
        return tk.Frame(parent, bg=WHITE, padx=padx, pady=pady, highlightthickness=1,
                        highlightbackground=BORDER)

    def set_details(self, text):
        self.details.configure(state="normal")
        self.details.delete("1.0", "end")
        self.details.insert("1.0", self.tr(text), "alignment")
        self.details.configure(state="disabled")
        self.details.yview_moveto(0)

    def set_busy(self, busy):
        for widget in (self.start_button, self.url_entry, self.timeout_entry, self.permission, self.privacy, self.standard_button, self.inventory_button, self.spec_button):
            widget.configure(state="disabled" if busy else "normal")
        self.cancel_button.configure(state="normal" if busy else "disabled")
        self.language_box.configure(state="disabled" if busy else "readonly")
        for button in [*self.export_buttons, self.http_button]:
            button.configure(state="normal" if self.report and not busy else "disabled")
        if busy:
            self.progress.pack(side="right", padx=8)
            self.progress.start(12)
        else:
            self.progress.stop()
            self.progress.pack_forget()

    def open_api_spec(self):
        path = filedialog.askopenfilename(parent=self.root, filetypes=[("OpenAPI JSON", "*.json")])
        if not path:
            return
        try:
            rows = inspect_spec(path)
        except (OSError, ValueError, RecursionError):
            messagebox.showerror("OpenAPI",
                                 "Invalid OpenAPI 3 JSON file." if self.english else "تعذّر قراءة ملف OpenAPI 3 JSON.",
                                 parent=self.root)
            return
        labels = ({"optional": "Authentication optional", "required": "Authentication declared",
                   "none": "No security declared", "reference": "Reference not loaded"} if self.english else
                  {"optional": "المصادقة اختيارية", "required": "المصادقة مطلوبة في المواصفة",
                   "none": "لا يوجد تصريح أمني في المواصفة", "reference": "مرجع لم يُحمّل"})
        intro = ("Document declarations. Runtime behavior is unverified." if self.english else
                 "هذه تصريحات المواصفة. سلوك الخادم يحتاج تحققًا مستقلًا.")
        show_text(self, "OpenAPI", "\n".join([intro, "", *[
            f"{method} {route}  |  {labels[state]}" for method, route, state in rows
        ]]))

    def discover_links(self):
        path = filedialog.askopenfilename(parent=self.root, filetypes=[("HTML", "*.html *.htm")])
        if not path:
            return
        try:
            urls = discover_saved_html(self.url.get(), path)
        except (OSError, ValueError):
            messagebox.showerror(self.tr("روابط من HTML"),
                                 self.tr("تعذّرت قراءة صفحة HTML المحلية."), parent=self.root)
            return
        show_text(self, self.tr("روابط داخلية مقترحة"), ",\n".join(urls))

    def import_url_inventory(self):
        files = filedialog.askopenfilenames(parent=self.root, filetypes=[("Sitemap / OpenAPI", "*.xml *.json")])
        if not files:
            return
        try:
            urls, skipped = import_inventory(self.url.get(), files)
        except (ValueError, OSError, ParseError, RecursionError) as error:
            messagebox.showerror("Sitemap / OpenAPI", str(error), parent=self.root)
            return
        if not urls:
            messagebox.showinfo("Sitemap / OpenAPI", "No new in-scope URLs." if self.english else
                                "ما فيه روابط إضافية ضمن النطاق.", parent=self.root)
            return
        self.start(standard=True, suggested=urls, skipped=skipped)

    def start(self, standard=False, suggested=None, skipped=0):
        if self.cancel is not None:
            return
        if not self.authorized.get():
            messagebox.showwarning(self.tr("صلاحية الفحص"), self.tr("أكد أن لديك صلاحية لفحص هذا الموقع."), parent=self.root)
            return
        try:
            url = normalize_url(self.url.get())
        except ValueError as error:
            messagebox.showerror(self.tr("راجع المدخلات"), self.error_message(str(error)), parent=self.root)
            return
        try:
            timeout = int(self.timeout.get())
            if not 1 <= timeout <= 60:
                raise ValueError
        except ValueError:
            messagebox.showerror(self.tr("مهلة غير صالحة"), self.tr("اختر مهلة من 1 إلى 60 ثانية."), parent=self.root)
            return
        urls = None
        if standard:
            if suggested is not None:
                prompt = (f"{len(suggested)} candidates; {skipped} skipped. Review before scanning." if self.english else
                          f"{len(suggested)} رابط مرشح، واستُبعد {skipped}. راجع القائمة قبل الفحص.")
                accepted = self.review_inventory(prompt, suggested)
                if accepted is None:
                    return
                suggested = accepted
            entries = ",".join(suggested) if suggested is not None else simpledialog.askstring(
                self.tr("تدقيق قائمة روابط"),
                self.tr("أدخل روابط مصرّح بها من نفس الأصل، مفصولة بفواصل. تُحفظ المسارات في مساحة العمل والسجل."),
                parent=self.root,
            )
            if entries is None:
                return
            try:
                urls = scope_urls(url, entries.split(","))
            except ValueError as error:
                messagebox.showerror(self.tr("راجع المدخلات"), str(error), parent=self.root)
                return
        hide_path = self.hide_path.get()
        self.report = None
        self.filter.set(self.tr("الكل"))
        self.render_findings()
        for label in self.counts.values():
            label.configure(text="—")
        self.coverage.set(public_url(url, hide_path))
        self.status.set(self.tr("جارٍ الاتصال بالصفحة…"))
        self.cancel = threading.Event()
        self.set_busy(True)
        threading.Thread(target=self.run_scan, args=(url, timeout, hide_path, self.cancel, urls),
                         daemon=True).start()
        self.root.after(50, self.poll)

    def review_inventory(self, prompt, suggested):
        dialog = tk.Toplevel(self.root)
        dialog.title("Sitemap / OpenAPI")
        dialog.transient(self.root)
        dialog.geometry("780x450")
        ttk.Label(dialog, text=prompt, padding=10).pack(fill="x")
        controls = ttk.Frame(dialog, padding=8)
        controls.pack(side="bottom", fill="x")
        text = tk.Text(dialog, wrap="none", padx=10, pady=10)
        text.pack(fill="both", expand=True)
        text.insert("1.0", "\n".join(suggested))
        approved = None

        def accept():
            nonlocal approved
            approved = text.get("1.0", "end-1c").splitlines()
            dialog.destroy()

        ttk.Button(controls, text=self.tr("بدء التدقيق"), command=accept).pack(side="left")
        ttk.Button(controls, text=self.tr("إلغاء"), command=dialog.destroy).pack(side="left", padx=8)
        dialog.grab_set()
        self.root.wait_window(dialog)
        return approved

    def run_scan(self, url, timeout, hide_path, cancel, urls):
        try:
            if urls is not None:
                self.messages.put(("batch", (urls, audit_urls(urls, timeout, cancel))))
                return
            report = scan(url, timeout, hide_path=hide_path, cancel=cancel)
        except ValueError as error:
            self.messages.put(("error", str(error)))
        except Exception:
            self.messages.put(("error", "حدث خطأ داخلي أثناء تشغيل التدقيق."))
        else:
            self.messages.put(("success", report))

    def cancel_scan(self):
        if self.cancel:
            self.cancel.set()
            self.cancel_button.configure(state="disabled")
            self.status.set(self.tr("جارٍ إلغاء الفحص…"))

    def poll(self):
        try:
            kind, payload = self.messages.get_nowait()
        except queue.Empty:
            self.root.after(50, self.poll)
            return
        cancelled = self.cancel.is_set()
        self.cancel = None
        if self.closing:
            self.root.destroy()
            return
        if cancelled and kind != "batch":
            self.status.set(self.tr("أُلغي الفحص"))
            self.set_details("يمكنك بدء فحص جديد.")
        elif kind == "error":
            self.status.set(self.tr("تعذّر إكمال الفحص"))
            self.set_details(self.error_message(payload))
        elif kind == "batch":
            urls, entries = payload
            saved = True
            for url in urls:
                register_asset(self.workspace, url)
            successful = [report for _, report in entries if report is not None]
            self.workspace["last_batch"] = {
                "requested": len(urls), "responses": len(successful),
                "errors": [url for url, report in entries if report is None],
                "not_attempted": urls[len(entries):],
            }
            for report in successful:
                record_scan(self.workspace, report)
                saved = self.save_history(report) and saved
            if successful:
                self.show_report(successful[0])
            self.status.set(
                f"{len(successful)}/{len(urls)} responses recorded in Workspace" if self.english else
                f"تم تسجيل {len(successful)} من {len(urls)} استجابة في مساحة التدقيق"
            )
            if not saved:
                self.history_error()
            self.open_workspace()
            self.workspace_panel.refresh()
            labels = ({"complete": "Complete", "redirect": "Redirect", "http_error": "HTTP error",
                       "limited": "Partial coverage", "failed": "No response", "not_attempted": "Not attempted"}
                      if self.english else
                      {"complete": "اكتمل", "redirect": "تحويل", "http_error": "خطأ HTTP",
                       "limited": "تغطية جزئية", "failed": "تعذّر الحصول على رد", "not_attempted": "لم يُفحص"})
            show_text(self, "URL coverage" if self.english else "تغطية الروابط", "\n".join(
                f"{labels[state]}{f' (HTTP {status})' if status is not None else ''}  |  {url}"
                for url, state, status in batch_rows(urls, entries)
            ))
        else:
            self.show_report(payload)
            if not self.save_history(payload):
                self.history_error()
        self.set_busy(False)

    def save_history(self, report):
        try:
            save_scan(history_path(), report)
        except (OSError, sqlite3.Error):
            return False
        return True

    def history_error(self):
        messagebox.showwarning(self.tr("سجل الفحوصات"),
                               self.tr("تعذّر الوصول إلى السجل المحلي."), parent=self.root)

    def error_message(self, text):
        if not self.english:
            return text
        if text.startswith("تعذر التحقق من شهادة TLS. رمز التحقق "):
            return f"TLS certificate verification failed (code {text.rsplit(' ', 1)[-1].rstrip('.')})."
        return ERRORS.get(text, EN.get(text, "The assessment could not be completed."))

    def show_report(self, report):
        self.report = report
        counts = Counter(item["severity"] for item in report["findings"])
        for level, label in self.counts.items():
            label.configure(text=counts[level])
        response_names = RESPONSE_EN if self.english else {
            "response": "استجابة", "redirect": "تحويل", "error": "استجابة خطأ"
        }
        response_label = response_names[report["response_kind"]]
        html_names = HTML_STATUS_EN if self.english else HTML_STATUS
        self.coverage.set(f'{response_label}  HTTP {report["status"]}    |    '
                          f'{html_names[report["html_status"]]}    |    {report["url"]}')
        count = len(report["findings"])
        noun = ("finding" if count == 1 else "findings") if self.english else "ملاحظة"
        self.status.set(f"{count} {noun}  ·  {response_label}")
        score = report.get("configuration_score")
        if score:
            self.coverage.set(self.coverage.get() +
                              f"    |    {self.tr('درجة الإعدادات الأمنية')}: {score['value']}/100")
        self.render_findings()

    def render_findings(self):
        self.table.delete(*self.table.get_children())
        self.copy_button.configure(state="disabled")
        self.set_details("اختر ملاحظة لعرض دليلها وتوصية الإصلاح.")
        if not self.report:
            return
        selected_filter = self.filter.get()
        for index, finding in enumerate(self.report["findings"]):
            severity = finding["severity"]
            if selected_filter in (self.tr("الكل"), self.severity_names[severity]):
                item = english_finding(finding) if self.english else finding
                self.table.insert("", "end", iid=str(index), tags=(severity,),
                                  values=(item["message"], item["id"], self.severity_names[severity]))
        if not self.table.get_children():
            self.set_details(self.tr("لا توجد ملاحظات ضمن العرض الحالي.") +
                             "\n\n" + "\n".join(self.limitations()))

    def show_selection(self):
        selection = self.table.selection()
        if not selection or not self.report:
            return
        item = self.report["findings"][int(selection[0])]
        if self.english:
            item = english_finding(item)
            evidence, impact, remedy = "Evidence", "Potential impact", "Remediation"
        else:
            evidence, impact, remedy = "الدليل", "سبب التصنيف", "الإجراء"
        self.set_details(f'{item["message"]}\n{self.tr("الرابط المتأثر")}: {self.report["url"]}\n'
                         f'{self.tr("الثقة")}: {self.tr("مؤشر يحتاج مراجعة")}\n{evidence}: {item["evidence"]}\n'
                         f'{impact}: {item["severity_reason"]}\n{remedy}: {item["recommendation"]}'
                         '\n\n' + '\n'.join(self.limitations()))
        self.copy_button.configure(state="normal")

    def limitations(self):
        return self.report["limitations_en" if self.english else "limitations"]

    def copy(self):
        if self.table.selection():
            self.root.clipboard_clear()
            self.root.clipboard_append(self.details.get("1.0", "end-1c"))
            self.status.set(self.tr("نُسخت الملاحظة"))

    def export(self, fmt):
        if not self.report:
            return
        extension = fmt.lower()
        name = filedialog.asksaveasfilename(parent=self.root, title=self.tr("حفظ تقرير WebGuard"),
                                             defaultextension=f".{extension}",
                                             initialfile=f"WebGuard_Report.{extension}",
                                             filetypes=[(fmt, f"*.{extension}")])
        if not name:
            return
        try:
            destination = Path(name)
            if fmt == "PDF":
                pdf_report(self.report, destination)
            else:
                content = (html_report(self.report, english=self.english) if fmt == "HTML" else
                           json.dumps(self.report, ensure_ascii=False, indent=2))
                destination.write_text(content, encoding="utf-8")
        except ImportError:
            messagebox.showerror(self.tr("تعذّر الحفظ"),
                                 self.tr("تحتاج إلى تثبيت اعتماديات التقارير من requirements-report.txt."),
                                 parent=self.root)
        except OSError:
            messagebox.showerror(self.tr("تعذّر الحفظ"),
                                 self.tr("تعذّر كتابة التقرير في المسار المحدد."), parent=self.root)
        else:
            self.status.set(f"{fmt} report saved" if self.english else f"حُفظ تقرير {fmt}")

    def open_workspace(self):
        if self.workspace_panel:
            self.workspace_panel.window.lift()
        else:
            self.workspace_panel = WorkspacePanel(self)

    def close(self):
        if self.cancel:
            self.closing = True
            self.cancel_scan()
            self.root.withdraw()
        else:
            self.root.destroy()


def main():
    if sys.platform == "win32":
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("WebGuard.Desktop")
    root = tk.Tk()
    if sys.platform == "win32":
        root.iconbitmap(default=str(Path(__file__).with_name("webguard.ico")))
    WebGuardApp(root)
    root.mainloop()


if __name__ == "__main__":
    mp.freeze_support()
    main()
