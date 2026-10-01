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
            f"<b>Classification:</b> {_esc(report.classification)}<br/>"
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
    if report.export_warnings:
        for warn in report.export_warnings[:5]:
            story.append(
                Paragraph(
                    f"<b>WARNING:</b> {_esc(warn)}",
                    ParagraphStyle(
                        "EngWarn",
                        parent=small,
                        textColor=colors.HexColor("#b45309"),
                    ),
                )
            )
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

    story.append(Paragraph(_esc(report.limitations.heading), h2))
    story.append(Paragraph(_esc(report.limitations.summary), body))
    if report.limitations.narrative:
        story.append(Paragraph(_esc(report.limitations.narrative), small))

    story.append(Paragraph(_esc(report.playbook.heading), h2))
    story.append(Paragraph(_esc(report.playbook.summary), body))
    if report.playbook.narrative:
        story.append(Paragraph(_esc(report.playbook.narrative), small))
    if report.playbook.metrics:
        rows = [["Step", "Status"]]
        for key, value in list(report.playbook.metrics.items())[:12]:
            rows.append([_esc(str(key)), _esc(_fmt(value))])
        story.append(_table(rows, col_widths=[70 * mm, 100 * mm]))
    if report.dual_control:
        story.append(
            Paragraph(
                f"<b>Dual control:</b> approved="
                f"{_esc(str(report.dual_control.get('approved')))} · "
                f"delivery={_esc(str(report.delivery))} · "
                f"SoD={_esc(str(report.dual_control.get('sod') or 'n/a'))}",
                small,
            )
        )

    story.append(Paragraph(_esc(report.ptes_checklist.heading), h2))
    story.append(Paragraph(_esc(report.ptes_checklist.summary), body))
    if report.ptes_checklist.narrative:
        story.append(Paragraph(_esc(report.ptes_checklist.narrative), small))
    if report.ptes_checklist.tables:
        tbl = report.ptes_checklist.tables[0]
        rows = [list(tbl.get("columns") or [])]
        for r in (tbl.get("rows") or [])[:12]:
            rows.append([_esc(str(c)) for c in r])
        if len(rows) > 1:
            story.append(_table(rows, col_widths=[40 * mm, 25 * mm, 20 * mm, 85 * mm]))

    story.append(Paragraph(_esc(report.asvs_checklist.heading), h2))
    story.append(Paragraph(_esc(report.asvs_checklist.summary), body))
    if report.asvs_checklist.narrative:
        story.append(Paragraph(_esc(report.asvs_checklist.narrative), small))
    if report.asvs_checklist.tables:
        tbl = report.asvs_checklist.tables[0]
        rows = [list(tbl.get("columns") or [])]
        for r in (tbl.get("rows") or [])[:14]:
            rows.append([_esc(str(c)) for c in r])
        if len(rows) > 1:
            story.append(_table(rows, col_widths=[15 * mm, 70 * mm, 30 * mm, 25 * mm]))

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
        rows = [["Sev", "Status", "Verify", "Asset", "Title"]]
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
            rows.append(
                [
                    _esc(sev),
                    _esc(status),
                    _esc(finding.verification_state)[:18],
                    _esc(finding.asset_name)[:20],
                    _esc(finding.title)[:40],
                ]
            )
        story.append(
            _table(rows, col_widths=[16 * mm, 22 * mm, 28 * mm, 30 * mm, 58 * mm])
        )

    if report.remediation_highlights:
        story.append(Paragraph("Remediation highlights", h2))
        for idx, item in enumerate(report.remediation_highlights, start=1):
            story.append(Paragraph(f"{idx}. {_esc(item)}", body))

    story.append(Paragraph(_esc(report.retest_summary.heading), h2))
    story.append(Paragraph(_esc(report.retest_summary.summary), body))
    if report.retest_summary.narrative:
        story.append(Paragraph(_esc(report.retest_summary.narrative), small))

    if report.verification_matrix:
        story.append(Paragraph("Verification matrix (before → after)", h2))
        rows = [["Sev", "Title", "Before", "After", "Gap"]]
        for row in report.verification_matrix[:35]:
            sev = (
                row.severity.value
                if hasattr(row.severity, "value")
                else str(row.severity)
            )
            rows.append(
                [
                    _esc(sev),
                    _esc(row.title)[:36],
                    _esc(row.before)[:16],
                    _esc(row.after)[:28],
                    _esc(row.gap or "—")[:28],
                ]
            )
        story.append(
            _table(rows, col_widths=[16 * mm, 48 * mm, 24 * mm, 40 * mm, 36 * mm])
        )

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
