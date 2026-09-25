"""Render ComplianceReport models to PDF bytes (ReportLab)."""

from __future__ import annotations

from io import BytesIO
from typing import TYPE_CHECKING

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

if TYPE_CHECKING:
    from app.schemas.reports import ComplianceReport


def render_compliance_pdf(report: ComplianceReport) -> bytes:
    """Convert a ComplianceReport into a downloadable PDF document."""
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=16 * mm,
        rightMargin=16 * mm,
        topMargin=14 * mm,
        bottomMargin=14 * mm,
        title=report.metadata.title,
        author=report.metadata.auditor_name,
    )
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "NexTitle",
        parent=styles["Heading1"],
        fontSize=16,
        spaceAfter=6,
        textColor=colors.HexColor("#0f172a"),
    )
    h2 = ParagraphStyle(
        "NexH2",
        parent=styles["Heading2"],
        fontSize=12,
        spaceBefore=10,
        spaceAfter=4,
        textColor=colors.HexColor("#1e293b"),
    )
    body = ParagraphStyle(
        "NexBody",
        parent=styles["Normal"],
        fontSize=9,
        leading=12,
        alignment=TA_LEFT,
    )
    small = ParagraphStyle(
        "NexSmall",
        parent=styles["Normal"],
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#475569"),
    )

    story: list = []
    meta = report.metadata
    story.append(Paragraph(_esc(meta.title), title_style))
    story.append(
        Paragraph(
            f"<b>Standard:</b> {_esc(meta.standard)} &nbsp;|&nbsp; "
            f"<b>Generated:</b> {_esc(meta.generated_at.isoformat())}<br/>"
            f"<b>Auditor:</b> {_esc(meta.auditor_name)} ({_esc(meta.auditor_email)}) "
            f"· {_esc(meta.auditor_role)}<br/>"
            f"<b>Scope:</b> {meta.scope_total_assets} assets "
            f"({meta.scope_cde_assets} CDE) · {meta.scope_active_findings} active findings",
            small,
        )
    )
    story.append(Spacer(1, 6))
    story.append(Paragraph("Executive summary", h2))
    story.append(Paragraph(_esc(report.executive_summary), body))

    for section in report.sections:
        story.append(Paragraph(_esc(section.heading), h2))
        story.append(Paragraph(_esc(section.summary), body))
        if section.narrative:
            story.append(Paragraph(_esc(section.narrative), small))
        if section.metrics:
            rows = [["Metric", "Value"]]
            for key, value in list(section.metrics.items())[:12]:
                rows.append([_esc(str(key)), _esc(_fmt(value))])
            story.append(_table(rows, col_widths=[70 * mm, 100 * mm]))

    if report.control_mapping:
        story.append(Paragraph("Control mapping", h2))
        rows = [["Control", "Title", "Findings", "Critical", "High"]]
        for bucket in report.control_mapping[:40]:
            sev = bucket.severity_summary or {}
            rows.append(
                [
                    _esc(bucket.control_id),
                    _esc(bucket.control_title)[:48],
                    str(bucket.finding_count),
                    str(sev.get("critical", 0)),
                    str(sev.get("high", 0)),
                ]
            )
        story.append(_table(rows, col_widths=[28 * mm, 70 * mm, 22 * mm, 22 * mm, 22 * mm]))

    if report.findings:
        story.append(Paragraph("Findings (sample)", h2))
        rows = [["Severity", "Status", "Asset", "Title", "Controls"]]
        for finding in report.findings[:60]:
            rows.append(
                [
                    _esc(str(finding.severity.value if hasattr(finding.severity, "value") else finding.severity)),
                    _esc(str(finding.status.value if hasattr(finding.status, "value") else finding.status)),
                    _esc(finding.asset_name)[:28],
                    _esc(finding.title)[:48],
                    _esc(", ".join(finding.controls[:3]) or "—"),
                ]
            )
        story.append(
            _table(rows, col_widths=[22 * mm, 24 * mm, 32 * mm, 55 * mm, 35 * mm])
        )

    if report.recommendations:
        story.append(Paragraph("Recommendations", h2))
        for idx, rec in enumerate(report.recommendations, start=1):
            story.append(Paragraph(f"{idx}. {_esc(rec)}", body))

    story.append(Spacer(1, 10))
    story.append(
        Paragraph(
            f"NexuSec compliance export · report_id={meta.report_id} · format=pdf",
            small,
        )
    )
    doc.build(story)
    return buffer.getvalue()


def _table(rows: list[list[str]], *, col_widths: list[float]) -> Table:
    table = Table(rows, colWidths=col_widths, repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 7),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f1f5f9")]),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 3),
                ("RIGHTPADDING", (0, 0), (-1, -1), 3),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]
        )
    )
    return table


def _esc(value: str) -> str:
    return (
        (value or "")
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def _fmt(value: object) -> str:
    if isinstance(value, dict):
        parts = [f"{k}={v}" for k, v in list(value.items())[:8]]
        return ", ".join(parts)
    if isinstance(value, list):
        return ", ".join(str(v) for v in value[:12])
    return str(value)
