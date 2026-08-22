from __future__ import annotations

from datetime import datetime
from io import BytesIO
from pathlib import Path
from typing import List, Optional

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table,
                                 TableStyle, PageBreak)

from phishguard.report_store import ReportStore

GITHUB_URL = "https://github.com/iampopg/PhishGuard"
AUTHOR = "@iampopg"

VERDICT_COLORS = {
    "safe": colors.HexColor("#10b981"),
    "suspicious": colors.HexColor("#f59e0b"),
    "phishing": colors.HexColor("#f97316"),
    "malicious": colors.HexColor("#ef4444"),
}

BRAND = colors.HexColor("#3b82f6")
DARK = colors.HexColor("#0f1722")
MUTED = colors.HexColor("#6b7280")


def generate_report_pdf(
    reports: List[dict],
    output_path: str,
    verdict_filter: Optional[str] = None,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
) -> bytes:
    """Build a beautiful PDF analysis report, signed with the author and repo."""
    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4,
                            leftMargin=1.8 * cm, rightMargin=1.8 * cm,
                            topMargin=1.8 * cm, bottomMargin=1.8 * cm)
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("brand", parent=styles["Title"], fontSize=22,
                                  textColor=BRAND, spaceAfter=2)
    sub_style = ParagraphStyle("sub", parent=styles["Normal"], fontSize=10,
                                textColor=MUTED, spaceAfter=10)
    h2_style = ParagraphStyle("h2", parent=styles["Heading2"], fontSize=14,
                               textColor=DARK, spaceBefore=10, spaceAfter=6)
    cell_style = ParagraphStyle("cell", parent=styles["Normal"], fontSize=8.5,
                                 textColor=DARK)
    footer_style = ParagraphStyle("footer", parent=styles["Normal"], fontSize=8,
                                   textColor=MUTED, alignment=1)

    story = []

    story.append(Paragraph("PhishGuard", title_style))
    story.append(Paragraph("Email Security · Analysis Report", sub_style))

    filters = []
    if verdict_filter:
        filters.append(f"Verdict: {verdict_filter}")
    if date_from:
        filters.append(f"From: {date_from}")
    if date_to:
        filters.append(f"To: {date_to}")
    meta = f"{len(reports)} report{'s' if len(reports) != 1 else ''}"
    if filters:
        meta += " · " + " · ".join(filters)
    meta += f" · Generated {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    story.append(Paragraph(meta, sub_style))
    story.append(Spacer(1, 6))

    counts = {}
    for r in reports:
        counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
    stat_cells = [Paragraph(f"<b>{v.upper()}</b><br/>{counts.get(v, 0)}", cell_style)
                  for v in ("safe", "suspicious", "phishing", "malicious")]
    stat_table = Table([stat_cells], colWidths=[4 * cm] * 4)
    stat_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f1f5f9")),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#1e293b")),
        ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#334155")),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    story.append(stat_table)
    story.append(Spacer(1, 12))

    story.append(Paragraph("Analyses", h2_style))

    header = [Paragraph("<b>Subject</b>", cell_style),
              Paragraph("<b>Sender</b>", cell_style),
              Paragraph("<b>Verdict</b>", cell_style),
              Paragraph("<b>Score</b>", cell_style),
              Paragraph("<b>Time</b>", cell_style)]
    rows = [header]
    for rep in reports:
        subj = (rep.get("source", {}) or {}).get("subject") or "(no subject)"
        sender = rep.get("sender", {}).get("from", "")
        rows.append([
            Paragraph(subj[:60], cell_style),
            Paragraph(sender[:35], cell_style),
            Paragraph(rep.get("verdict", ""), cell_style),
            Paragraph(str(rep.get("risk_score", "")), cell_style),
            Paragraph(rep.get("timestamp", "")[:19].replace("T", " "), cell_style),
        ])

    t = Table(rows, colWidths=[6.5 * cm, 4.5 * cm, 2.5 * cm, 1.8 * cm, 3.5 * cm],
              repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), DARK),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 9),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#1e293b")),
        ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    story.append(t)
    story.append(Spacer(1, 16))

    story.append(Paragraph("This report was generated by PhishGuard, an open-source "
                            "email security engine.", footer_style))
    story.append(Paragraph(f"Authored by {AUTHOR} · {GITHUB_URL}", footer_style))

    doc.build(story, onFirstPage=_add_page_footer, onLaterPages=_add_page_footer)

    data = buf.getvalue()
    if output_path:
        Path(output_path).write_bytes(data)
    return data


def _add_page_footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(MUTED)
    canvas.drawString(1.8 * cm, 1 * cm,
                      f"PhishGuard · {AUTHOR} · {GITHUB_URL}")
    canvas.drawRightString(A4[0] - 1.8 * cm, 1 * cm, f"Page {doc.page}")
    canvas.restoreState()
