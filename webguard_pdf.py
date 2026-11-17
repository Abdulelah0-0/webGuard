"""Build a paginated English security assessment from a WebGuard result."""
from collections import Counter
from html import escape
from pathlib import Path

from webguard_english import HTML_STATUS_EN, RESPONSE_EN, SEVERITY_EN, english_finding

INK = "#142238"
MUTED = "#41536A"
LINE = "#D5DFEC"
BLUE = "#18488A"
SEVERITY_COLOR = {"high": "#A12434", "medium": "#805019", "low": BLUE, "info": MUTED}


def pdf_report(report: dict, destination: Path):
    # Import at export time so the response analyzer remains standard-library only.
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_LEFT
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.platypus import KeepTogether, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    def style(name, size=10, leading=14, bold=False, color=INK, after=0):
        return ParagraphStyle(name, fontName="Helvetica-Bold" if bold else "Helvetica",
                              fontSize=size, leading=leading, textColor=colors.HexColor(color),
                              spaceAfter=after, alignment=TA_LEFT, splitLongWords=True)

    def plain(value):
        # Built-in PDF fonts support WinAnsi. Represent other observed characters losslessly.
        return escape(str(value).encode("cp1252", "backslashreplace").decode("cp1252"))

    title = style("title", 26, 31, True, after=12)
    section = style("section", 15, 19, True, after=9)
    body = style("body", after=5)
    small = style("small", 9, 13, color=MUTED, after=4)
    stat = style("stat", 18, 22, True)
    doc = SimpleDocTemplate(str(destination), pagesize=A4, leftMargin=46, rightMargin=46,
                            topMargin=65, bottomMargin=53, title="WebGuard | Web Security Assessment",
                            author="WebGuard")
    counts = Counter(item["severity"] for item in report["findings"])
    story = [
        Paragraph("Web Security Assessment", title),
        Paragraph(f"<b>Target</b> {plain(report['url'])}", body),
        Paragraph(f"<b>Observed at</b> {plain(report['checked_at'])} (UTC)", body),
        Paragraph(f"<b>HTTP status</b> {report['status']} &nbsp; | &nbsp; "
                  f"{RESPONSE_EN[report['response_kind']]}", body),
        Paragraph(f"<b>Coverage</b> {HTML_STATUS_EN[report['html_status']]}", body),
    ]
    mode = {"quick": "Quick", "standard": "Standard (one response in a URL-list audit)"}
    if report.get("scan_mode") in mode:
        story.append(Paragraph(f"<b>Scan mode</b> {mode[report['scan_mode']]}", body))
    score = report.get("configuration_score")
    if score:
        story.append(Paragraph(f"<b>Configuration score</b> {score['value']}/100 for evaluated controls", body))
        for check in score["checks"]:
            reasons = ", ".join(check["reasons"])
            story.append(Paragraph(
                f"{plain(check['name'])}: {check['earned']}/{check['weight']} {plain(reasons)}", small))
    if report.get("title"):
        story.append(Paragraph(f"<b>Page title</b> {plain(report['title'])}", body))
    if "body_bytes_analyzed" in report:
        story.append(Paragraph(f"<b>Response body retained for analysis</b> "
                               f"{report['body_bytes_analyzed']:,} bytes", body))
    if report.get("tls"):
        tls = report["tls"]
        story.append(Paragraph(f"<b>TLS</b> {plain(tls['protocol'])} &nbsp; | &nbsp; "
                               f"<b>Certificate expiry</b> {plain(tls['expires'] or 'Unavailable')}", body))
    story.extend([Spacer(1, 12), Paragraph("Findings at a glance", section)])
    columns = []
    for key, label in SEVERITY_EN.items():
        columns.append([Paragraph(str(counts[key]), stat), Paragraph(label, small)])
    summary = Table([columns], colWidths=[doc.width / 4] * 4)
    summary.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#EFF4FA")),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor(LINE)),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor(LINE)),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 12),
        ("TOPPADDING", (0, 0), (-1, -1), 9),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.extend([summary, Spacer(1, 18), Paragraph("Scope and limitations", section)])
    for limitation in report["limitations_en"]:
        story.append(Paragraph(plain(limitation), small, bulletText="•"))
    story.extend([Spacer(1, 14), Paragraph("Findings and remediation", section)])
    if not report["findings"]:
        story.append(Paragraph("No findings were observed in the completed checks.", body))
    for number, finding in enumerate(report["findings"], 1):
        item = english_finding(finding)
        level = item["severity"]
        finding_title = style("finding-title", 12, 16, True, after=5)
        label = SEVERITY_EN[level].upper()
        story.append(KeepTogether([
            Paragraph(f'<font color="{SEVERITY_COLOR[level]}">{label}</font> &nbsp; {plain(item["id"])}', small),
            Paragraph(f"{number:02d}. {plain(item['message'])}", finding_title),
            Paragraph("<b>Confidence</b> Response-based indicator", body),
            Paragraph(f"<b>Evidence</b> {plain(item['evidence'])}", body),
            Paragraph(f"<b>Potential impact</b> {plain(item['severity_reason'])}", body),
            Paragraph(f"<b>Remediation</b> {plain(item['recommendation'])}", body),
            Spacer(1, 12),
        ]))

    def chrome(canvas, document):
        width, height = document.pagesize
        canvas.saveState()
        canvas.setStrokeColor(colors.HexColor(LINE))
        canvas.line(46, height - 48, width - 46, height - 48)
        canvas.line(46, 43, width - 46, 43)
        canvas.setFillColor(colors.HexColor(BLUE))
        canvas.setFont("Helvetica-Bold", 10)
        canvas.drawString(46, height - 36, f"WEBGUARD  /  {report['app_version']}")
        canvas.setFillColor(colors.HexColor(MUTED))
        canvas.setFont("Helvetica", 9)
        canvas.drawString(46, 29, "Web security assessment")
        canvas.drawRightString(width - 46, 29, f"Page {document.page}")
        canvas.restoreState()

    doc.build(story, onFirstPage=chrome, onLaterPages=chrome)
