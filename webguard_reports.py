"""Standalone, escaped Arabic reports with no network dependencies."""
from html import escape

from webguard import SEVERITY_AR
from webguard_english import HTML_STATUS_EN, SEVERITY_EN, english_finding

HTML_STATUS = {
    "not_applicable": "تحليل HTML غير منطبق",
    "empty": "رد HTML فارغ",
    "analyzed": "تم تحليل HTML",
    "partial": "تم تحليل جزء من HTML",
    "failed": "تعذّر تحليل HTML",
}


def html_report(report: dict, *, english=False) -> str:
    severity = SEVERITY_EN if english else SEVERITY_AR
    html_status = HTML_STATUS_EN if english else HTML_STATUS
    title = "WebGuard | Security Assessment" if english else "WebGuard | تقرير تدقيق الأمان"
    evidence, impact, remediation = (("Evidence", "Potential impact", "Remediation") if english else
                                      ("الدليل", "سبب التصنيف", "الإجراء المقترح"))
    scope = "Scope and limitations" if english else "نطاق الفحص"
    findings = []
    for item in report["findings"]:
        if english:
            item = english_finding(item)
        findings.append(
            "<article>"
            f"<h2>{escape(severity[item['severity']])} · {escape(item['message'])}</h2>"
            f"<p><code>{escape(item['id'])}</code></p>"
            f"<p><strong>{evidence}</strong> {escape(item['evidence'])}</p>"
            f"<p><strong>{impact}</strong> {escape(item['severity_reason'])}</p>"
            f"<p><strong>{remediation}</strong> {escape(item['recommendation'])}</p>"
            "</article>"
        )
    empty = ("No findings were observed in the completed checks." if english else
             "لم تظهر ملاحظات في الفحوصات المكتملة.")
    results = "".join(findings) or f"<p>{empty}</p>"
    limitations = "".join(f"<li>{escape(item)}</li>" for item in report["limitations_en" if english else "limitations"])
    return f"""<!doctype html>
<html lang="{'en' if english else 'ar'}" dir="{'ltr' if english else 'rtl'}">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>
body {{ margin: 0 auto; max-width: 850px; padding: 32px 20px; background: #f0f3f8;
       color: #101f36; font: 16px/1.65 "Segoe UI", sans-serif; }}
header, article, section {{ padding: 18px 22px; margin: 0 0 14px;
       background: #fff; border: 1px solid #dae2ee; border-radius: 8px; }}
header {{ background: #101f36; color: white; }}
h1, h2, p {{ margin: 0 0 8px; overflow-wrap: anywhere; }}
h2 {{ font-size: 18px; }}
code {{ direction: ltr; unicode-bidi: isolate; }}
@media print {{ body {{ background: white; }} article {{ break-inside: avoid; }}
               header {{ color: #101f36; background: white; }} }}
</style>
<header>
<h1>{title}</h1>
<p><bdi>{escape(report["url"])}</bdi></p>
<p><bdi>HTTP {report["status"]} · {escape(report["checked_at"])} · WebGuard {escape(report["app_version"])}</bdi></p>
<p>{escape(html_status[report["html_status"]])}</p>
</header>
<main>{results}<section><h2>{scope}</h2><ul>{limitations}</ul></section></main>
</html>
"""
