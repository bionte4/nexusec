"""Render EngagementReport models to PDF bytes (ReportLab)."""

from __future__ import annotations

from io import BytesIO
from typing import TYPE_CHECKING

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

if TYPE_CHECKING:
    from app.schemas.reports import EngagementReport


def render_engagement_pdf(report: EngagementReport) -> bytes:
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
        "EngTitle",
        parent=styles["Heading1"],
        fontSize=16,
        spaceAfter=6,
        textColor=colors.HexColor("#0f172a"),
    )
    h2 = ParagraphStyle(
        "EngH2",
        parent=styles["Heading2"],
        fontSize=12,
        spaceBefore=10,
        spaceAfter=4,
        textColor=colors.HexColor("#1e293b"),
    )
    body = ParagraphStyle(
        "EngBody",
        parent=styles["Normal"],
        fontSize=9,
        leading=12,
        alignment=TA_LEFT,
    )
    small = ParagraphStyle(
        "EngSmall",
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
            f"<b>Type:</b> {_esc(report.engagement_type.upper())} &nbsp;|&nbsp; "
            f"<b>Standard:</b> {_esc(meta.standard)}<br/>"
            f"<b>Generated:</b> {_esc(meta.generated_at.isoformat())}<br/>"
            f"<b>Prepared by:</b> {_esc(meta.auditor_name)} ({_esc(meta.auditor_email)}) "
            f"· {_esc(meta.auditor_role)}<br/>"
            f"<b>Scope:</b> {meta.scope_total_assets} assets "
            f"({meta.scope_cde_assets} CDE) · {meta.scope_active_findings} active findings",
            small,
        )
    )
    if meta.scope_notes:
        story.append(Paragraph(_esc(meta.scope_notes), small))
    story.append(Spacer(1, 6))

    story.append(Paragraph("Executive summary", h2))
    story.append(Paragraph(_esc(report.executive_summary), body))

    story.append(Paragraph(_esc(report.scope.heading), h2))
    story.append(Paragraph(_esc(report.scope.summary), body))
    if report.scope.narrative:
        story.append(Paragraph(_esc(report.scope.narrative), small))
    if report.scope.metrics:
        rows = [["Metric", "Value"]]
        for key, value in list(report.scope.metrics.items())[:12]:
            rows.append([_esc(str(key)), _esc(_fmt(value))])
        story.append(_table(rows, col_widths=[70 * mm, 100 * mm]))

    story.append(Paragraph(_esc(report.methodology.heading), h2))
    story.append(Paragraph(_esc(report.methodology.summary), body))
    if report.methodology.narrative:
        story.append(Paragraph(_esc(report.methodology.narrative), body))

    story.append(Paragraph("Severity & status summary", h2))
    sev_rows = [["Severity", "Count"]]
    for key in ("critical", "high", "medium", "low", "info", "unknown"):
        sev_rows.append([key, str(report.severity_summary.get(key, 0))])
    story.append(_table(sev_rows, col_widths=[70 * mm, 40 * mm]))
    story.append(Spacer(1, 4))
    st_rows = [["Status", "Count"]]
    for key, value in sorted(report.status_summary.items()):
        if value:
            st_rows.append([_esc(key), str(value)])
    if len(st_rows) > 1:
        story.append(_table(st_rows, col_widths=[70 * mm, 40 * mm]))

    if report.scans:
        story.append(Paragraph("Scans in engagement", h2))
        rows = [["Name", "Type", "Engine", "Status"]]
        for scan in report.scans[:30]:
            rows.append(
                [
                    _esc(scan.name)[:40],
                    _esc(scan.scan_type),
                    _esc(scan.engine),
                    _esc(scan.status),
                ]
            )
        story.append(_table(rows, col_widths=[70 * mm, 28 * mm, 28 * mm, 28 * mm]))

    if report.top_findings:
        story.append(Paragraph("Top findings", h2))
        rows = [["Sev", "Status", "Asset", "Title", "CWE/CVE"]]
        for finding in report.top_findings[:40]:
            sev = (
                finding.severity.value
                if hasattr(finding.severity, "value")
                else str(finding.severity)
            )
            status = (
                finding.status.value
                if hasattr(finding.status, "value")
                else str(finding.status)
            )
            ids = ", ".join(x for x in [finding.cwe_id, finding.cve_id] if x) or "—"
            rows.append(
                [
                    _esc(sev),
                    _esc(status),
                    _esc(finding.asset_name)[:22],
                    _esc(finding.title)[:42],
                    _esc(ids)[:28],
                ]
            )
        story.append(
            _table(rows, col_widths=[18 * mm, 24 * mm, 32 * mm, 55 * mm, 35 * mm])
        )

    if report.remediation_highlights:
        story.append(Paragraph("Remediation highlights", h2))
        for idx, item in enumerate(report.remediation_highlights, start=1):
            story.append(Paragraph(f"{idx}. {_esc(item)}", body))

    story.append(Paragraph(_esc(report.retest_summary.heading), h2))
    story.append(Paragraph(_esc(report.retest_summary.summary), body))
    if report.retest_summary.narrative:
        story.append(Paragraph(_esc(report.retest_summary.narrative), small))

    if report.recommendations:
        story.append(Paragraph("Recommendations", h2))
        for idx, rec in enumerate(report.recommendations, start=1):
            story.append(Paragraph(f"{idx}. {_esc(rec)}", body))

    story.append(Spacer(1, 10))
    story.append(Paragraph(_esc(report.disclaimer), small))
    story.append(
        Paragraph(
            f"NexuSec engagement export · report_id={meta.report_id} · format=pdf",
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
                (
                    "ROWBACKGROUNDS",
                    (0, 1),
                    (-1, -1),
                    [colors.white, colors.HexColor("#f1f5f9")],
                ),
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
