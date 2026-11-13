"""PDF report rendering with ReportLab.

A deliberately plain, dense document: cover page, summary, methodology,
limitations, application metadata, permissions, per-finding detail with
evidence, indicators and an analysis-metadata appendix. Text originating from
an analysed APK is escaped before it reaches ReportLab's mini-HTML parser, so a
crafted string in an APK cannot corrupt the document structure.
"""

from __future__ import annotations

import html
from datetime import UTC, datetime
from io import BytesIO
from typing import Any

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from app.reports.html import SEVERITY_ORDER, build_summary_text

# The PDF uses the standard Type 1 fonts, whose encoding lacks U+25CB (white
# circle) and U+25E6 -- both silently fall back to the filled square, which
# would make "info" indistinguishable from "medium".  A verified-distinct set
# is used here; the HTML report keeps its own glyphs, which browsers render.
SEVERITY_GLYPH = {
    "critical": "\u25c6",  # black diamond
    "high": "\u25b2",      # black up triangle
    "medium": "\u25a0",    # black square
    "low": "\u25cf",       # black circle
    "info": "\u00b7",      # middle dot
}

PAGE_SIZE = A4
MARGIN = 18 * mm

SEVERITY_COLOUR = {
    "critical": colors.HexColor("#7f1d1d"),
    "high": colors.HexColor("#9a3412"),
    "medium": colors.HexColor("#854d0e"),
    "low": colors.HexColor("#1e40af"),
    "info": colors.HexColor("#334155"),
}
INK = colors.HexColor("#0f172a")
MUTED = colors.HexColor("#475569")
LINE = colors.HexColor("#cbd5e1")
SURFACE = colors.HexColor("#f1f5f9")

MAX_SNIPPET_CHARS = 600
MAX_EVIDENCE_PER_FINDING = 4
MAX_FINDINGS_RENDERED = 400


def _styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "DsTitle", parent=base["Title"], fontSize=22, leading=27, textColor=INK,
            alignment=TA_LEFT, spaceAfter=4,
        ),
        "subtitle": ParagraphStyle(
            "DsSubtitle", parent=base["Normal"], fontSize=11, leading=15, textColor=MUTED,
            fontName="Courier", spaceAfter=14,
        ),
        "h2": ParagraphStyle(
            "DsH2", parent=base["Heading2"], fontSize=13.5, leading=17, textColor=INK,
            spaceBefore=16, spaceAfter=5,
        ),
        "h3": ParagraphStyle(
            "DsH3", parent=base["Heading3"], fontSize=10.5, leading=14, textColor=INK,
            spaceBefore=9, spaceAfter=3,
        ),
        "body": ParagraphStyle(
            "DsBody", parent=base["Normal"], fontSize=9, leading=12.6, textColor=INK,
            spaceAfter=4,
        ),
        "meta": ParagraphStyle(
            "DsMeta", parent=base["Normal"], fontSize=7.8, leading=10.5, textColor=MUTED,
            fontName="Courier", spaceAfter=3,
        ),
        "code": ParagraphStyle(
            "DsCode", parent=base["Normal"], fontSize=7.5, leading=10, fontName="Courier",
            textColor=colors.HexColor("#1e293b"), backColor=SURFACE,
            borderPadding=4, leftIndent=3, spaceBefore=2, spaceAfter=5,
        ),
        "cell": ParagraphStyle(
            "DsCell", parent=base["Normal"], fontSize=8, leading=11, textColor=INK,
        ),
        "cellmono": ParagraphStyle(
            "DsCellMono", parent=base["Normal"], fontSize=7.5, leading=10, fontName="Courier",
            textColor=INK,
        ),
    }


def esc(value: Any, limit: int = 4000) -> str:
    """Escape APK-derived text before ReportLab parses it as mini-HTML."""
    text = "" if value is None else str(value)
    if len(text) > limit:
        text = text[: limit - 1] + "…"
    return html.escape(text, quote=False)


def render_pdf(document: dict[str, Any]) -> bytes:
    styles = _styles()
    buffer = BytesIO()
    application = document.get("application", {})
    scan = document.get("scan", {})

    doc = SimpleDocTemplate(
        buffer,
        pagesize=PAGE_SIZE,
        leftMargin=MARGIN,
        rightMargin=MARGIN,
        topMargin=MARGIN,
        bottomMargin=MARGIN + 6 * mm,
        title=f"DroidScope report - {application.get('package_name') or 'application'}",
        author="DroidScope",
        subject="Android application security analysis",
    )

    story: list[Any] = []
    story += _cover(document, styles)
    story.append(PageBreak())
    story += _summary(document, styles)
    story += _methodology(document, styles)
    story += _limitations(document, styles)
    story += _application(document, styles)
    story += _permissions(document, styles)
    story += _findings(document, styles)
    story += _indicators(document, styles)
    story += _appendix(document, styles)

    doc.build(story, onFirstPage=_decorate, onLaterPages=_decorate)
    return buffer.getvalue()


def _decorate(canvas, doc) -> None:  # noqa: ANN001
    """Footer with page number and a non-repudiable scan reference."""
    canvas.saveState()
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(MUTED)
    canvas.drawString(MARGIN, 10 * mm, "DroidScope - Android application security analysis")
    canvas.drawRightString(
        PAGE_SIZE[0] - MARGIN, 10 * mm, f"page {canvas.getPageNumber()}"
    )
    canvas.setStrokeColor(LINE)
    canvas.setLineWidth(0.4)
    canvas.line(MARGIN, 13 * mm, PAGE_SIZE[0] - MARGIN, 13 * mm)
    canvas.restoreState()


def _kv_table(rows: list[tuple[str, str]], styles: dict, *, mono_values: bool = False) -> Table:
    value_style = styles["cellmono"] if mono_values else styles["cell"]
    data = [
        [Paragraph(f"<b>{esc(key)}</b>", styles["cell"]), Paragraph(esc(value), value_style)]
        for key, value in rows
    ]
    table = Table(data, colWidths=[42 * mm, None], hAlign="LEFT")
    table.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LINEBELOW", (0, 0), (-1, -2), 0.3, LINE),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("LEFTPADDING", (0, 0), (-1, -1), 0),
            ]
        )
    )
    return table


def _cover(document: dict[str, Any], styles: dict) -> list[Any]:
    application = document.get("application", {})
    scan = document.get("scan", {})
    risk = document.get("risk", {})
    report = document.get("report", {})
    counts = scan.get("severity_counts", {})

    story: list[Any] = [
        Spacer(1, 26 * mm),
        Paragraph("Android application<br/>security report", styles["title"]),
        HRFlowable(width="100%", thickness=1.1, color=INK, spaceBefore=6, spaceAfter=10),
        Paragraph(
            esc(application.get("package_name") or application.get("file_name") or "unknown"),
            styles["subtitle"],
        ),
    ]

    header = [
        Paragraph(f"<b>{esc(name.upper())}</b>", styles["cell"]) for name in SEVERITY_ORDER
    ]
    values = [
        Paragraph(f"{SEVERITY_GLYPH[name]} {counts.get(name, 0)}", styles["cell"])
        for name in SEVERITY_ORDER
    ]
    severity_table = Table([header, values], colWidths=[33 * mm] * 5, hAlign="LEFT")
    severity_table.setStyle(
        TableStyle(
            [
                ("BOX", (0, 0), (-1, -1), 0.5, LINE),
                ("INNERGRID", (0, 0), (-1, -1), 0.3, LINE),
                ("BACKGROUND", (0, 0), (-1, 0), SURFACE),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ]
            + [
                ("TEXTCOLOR", (index, 1), (index, 1), SEVERITY_COLOUR[name])
                for index, name in enumerate(SEVERITY_ORDER)
            ]
        )
    )
    story += [severity_table, Spacer(1, 10 * mm)]

    story.append(
        _kv_table(
            [
                ("Risk score", f"{risk.get('score', 'not calculated')} / 100 ({risk.get('band', 'unknown')})"),
                ("Findings", str(scan.get("findings_total", 0))),
                ("Scan profile", str(scan.get("profile", ""))),
                ("Scan status", str(scan.get("status", ""))),
                ("Scan identifier", str(scan.get("id", ""))),
                ("APK SHA-256", str(application.get("sha256", ""))),
                ("Generated", str(report.get("generated_at", ""))),
                ("Generator", str(report.get("generator", ""))),
            ],
            styles,
            mono_values=True,
        )
    )
    story += [
        Spacer(1, 8 * mm),
        Paragraph(
            "This report describes the application as shipped. It is not a guarantee "
            "of security, and the limitations section states what the analysis did "
            "not cover.",
            styles["meta"],
        ),
    ]
    return story


def _summary(document: dict[str, Any], styles: dict) -> list[Any]:
    risk = document.get("risk", {})
    story = [
        Paragraph("Executive summary", styles["h2"]),
        Paragraph(esc(build_summary_text(document)), styles["body"]),
        Spacer(1, 3 * mm),
        Paragraph("How the risk score is calculated", styles["h3"]),
        Paragraph(esc(risk.get("method", "")), styles["body"]),
    ]
    contributors = risk.get("top_contributors", [])
    if contributors:
        story.append(Paragraph("Largest contributors to the score", styles["h3"]))
        rows = [
            [
                Paragraph("<b>Rule</b>", styles["cell"]),
                Paragraph("<b>Severity</b>", styles["cell"]),
                Paragraph("<b>Confidence</b>", styles["cell"]),
                Paragraph("<b>Weight</b>", styles["cell"]),
            ]
        ]
        for item in contributors[:8]:
            rows.append(
                [
                    Paragraph(esc(item.get("rule_id")), styles["cellmono"]),
                    Paragraph(esc(item.get("severity")), styles["cell"]),
                    Paragraph(esc(item.get("confidence")), styles["cell"]),
                    Paragraph(esc(item.get("weight")), styles["cell"]),
                ]
            )
        story.append(_grid(rows, [50 * mm, 25 * mm, 28 * mm, 22 * mm]))
    return story


def _methodology(document: dict[str, Any], styles: dict) -> list[Any]:
    methodology = document.get("methodology", {})
    story = [
        Paragraph("Scope and methodology", styles["h2"]),
        Paragraph(esc(methodology.get("approach", "")), styles["body"]),
        Paragraph(esc(methodology.get("standards", "")), styles["body"]),
        Paragraph("Analyzer execution", styles["h3"]),
    ]
    rows = [
        [
            Paragraph("<b>Analyzer</b>", styles["cell"]),
            Paragraph("<b>Status</b>", styles["cell"]),
            Paragraph("<b>Findings</b>", styles["cell"]),
            Paragraph("<b>Duration</b>", styles["cell"]),
            Paragraph("<b>Notes</b>", styles["cell"]),
        ]
    ]
    for item in document.get("analyzers", []):
        rows.append(
            [
                Paragraph(esc(item.get("analyzer")), styles["cellmono"]),
                Paragraph(esc(item.get("status")), styles["cell"]),
                Paragraph(esc(item.get("findings")), styles["cell"]),
                Paragraph(f"{item.get('duration_seconds') or 0:.1f}s", styles["cell"]),
                Paragraph(esc(item.get("error") or "", 160), styles["cell"]),
            ]
        )
    story.append(_grid(rows, [38 * mm, 22 * mm, 18 * mm, 18 * mm, None]))
    return story


def _limitations(document: dict[str, Any], styles: dict) -> list[Any]:
    limitations = document.get("scope_and_limitations", {})
    story = [Paragraph("Limitations", styles["h2"])]
    for statement in limitations.get("statements", []):
        story.append(Paragraph(f"• {esc(statement)}", styles["body"]))
    return story


def _application(document: dict[str, Any], styles: dict) -> list[Any]:
    application = document.get("application", {})
    rows = [
        ("Package", application.get("package_name") or "not determined"),
        ("Label", application.get("label") or "not determined"),
        ("Version", f"{application.get('version_name') or '?'} (code {application.get('version_code') or '?'})"),
        ("Minimum SDK", application.get("min_sdk") or "?"),
        ("Target SDK", application.get("target_sdk") or "?"),
        ("File", f"{application.get('file_name')} ({application.get('file_size')} bytes)"),
        ("SHA-256", application.get("sha256")),
        ("SHA-1", application.get("sha1")),
        ("MD5", application.get("md5")),
        ("Signature schemes", ", ".join(application.get("signature_schemes", [])) or "none detected"),
        ("ABIs", ", ".join(application.get("abis", [])) or "none"),
        ("DEX files", str(len(application.get("dex_files", [])))),
        ("Native libraries", str(len(application.get("native_libraries", [])))),
        ("Components", str(len(application.get("components", [])))),
    ]
    story = [
        Paragraph("Application metadata", styles["h2"]),
        _kv_table(rows, styles, mono_values=True),
    ]
    certificates = application.get("certificates", [])
    if certificates:
        story.append(Paragraph("Signing certificates", styles["h3"]))
        for cert in certificates[:4]:
            story.append(
                _kv_table(
                    [
                        ("Subject", cert.get("subject") or "unknown"),
                        ("Issuer", cert.get("issuer") or "unknown"),
                        ("Algorithm", cert.get("signature_algorithm") or "unknown"),
                        ("Key size", f"{cert.get('key_size_bits') or '?'} bits"),
                        ("Valid from", cert.get("not_before") or "?"),
                        ("Valid to", cert.get("not_after") or "?"),
                        ("SHA-256", cert.get("sha256_fingerprint") or "?"),
                        ("Self signed", "yes" if cert.get("is_self_signed") else "no"),
                    ],
                    styles,
                    mono_values=True,
                )
            )
            story.append(Spacer(1, 3 * mm))
    if application.get("metadata_errors"):
        story.append(Paragraph("Metadata parsing issues", styles["h3"]))
        for error in application["metadata_errors"][:10]:
            story.append(Paragraph(f"• {esc(error)}", styles["body"]))
    return story


def _permissions(document: dict[str, Any], styles: dict) -> list[Any]:
    analysis = document.get("permission_analysis", {})
    story = [
        Paragraph("Permission analysis", styles["h2"]),
        Paragraph(
            f"{analysis.get('total', 0)} permissions requested, "
            f"{analysis.get('dangerous_count', 0)} classified dangerous by the platform.",
            styles["body"],
        ),
    ]
    permissions = analysis.get("all", [])
    if not permissions:
        return story
    rows = [
        [
            Paragraph("<b>Permission</b>", styles["cell"]),
            Paragraph("<b>Protection level</b>", styles["cell"]),
            Paragraph("<b>Dangerous</b>", styles["cell"]),
        ]
    ]
    for permission in permissions[:120]:
        rows.append(
            [
                Paragraph(esc(permission.get("name")), styles["cellmono"]),
                Paragraph(esc(permission.get("protection_level") or "unknown"), styles["cell"]),
                Paragraph("yes" if permission.get("is_dangerous") else "no", styles["cell"]),
            ]
        )
    story.append(_grid(rows, [None, 38 * mm, 22 * mm]))
    return story


def _findings(document: dict[str, Any], styles: dict) -> list[Any]:
    findings = document.get("findings", [])
    story: list[Any] = [PageBreak(), Paragraph("Findings", styles["h2"])]

    if not findings:
        story.append(
            Paragraph(
                "No findings were produced by the analyzers that ran. This is not "
                "evidence that the application is secure; see the limitations section.",
                styles["body"],
            )
        )
        return story

    for index, finding in enumerate(findings[:MAX_FINDINGS_RENDERED], start=1):
        severity = str(finding.get("severity", "info"))
        block: list[Any] = [
            Paragraph(
                f'<font color="{SEVERITY_COLOUR.get(severity, INK).hexval()}">'
                f"<b>{SEVERITY_GLYPH.get(severity, '')} {esc(severity.upper())}</b></font>"
                f" &nbsp;{index}. {esc(finding.get('title'), 300)}",
                styles["h3"],
            ),
            Paragraph(
                " &middot; ".join(
                    filter(
                        None,
                        [
                            esc(finding.get("rule_id")),
                            f"confidence: {esc(finding.get('confidence'))}",
                            f"engine: {esc(finding.get('analysis_engine'))}",
                            f"status: {esc(finding.get('status'))}",
                            ", ".join(finding.get("cwe_ids", [])) or None,
                            ", ".join(finding.get("masvs_controls", [])) or None,
                        ],
                    )
                ),
                styles["meta"],
            ),
            Paragraph(esc(finding.get("description")), styles["body"]),
        ]

        location = finding.get("affected_component") or ""
        if finding.get("file_path"):
            location = f"{location} — {finding['file_path']}"
            if finding.get("line_number"):
                location += f":{finding['line_number']}"
        if location.strip():
            block.append(Paragraph(esc(location, 300), styles["meta"]))

        block.append(Paragraph(f"<b>Impact.</b> {esc(finding.get('impact'))}", styles["body"]))
        block.append(
            Paragraph(f"<b>Remediation.</b> {esc(finding.get('remediation'))}", styles["body"])
        )
        if finding.get("verification"):
            block.append(
                Paragraph(f"<b>Verification.</b> {esc(finding['verification'])}", styles["body"])
            )
        if finding.get("limitations"):
            block.append(
                Paragraph(
                    f"<b>Detection limitations.</b> {esc(finding['limitations'])}", styles["body"]
                )
            )

        for item in (finding.get("evidence") or [])[:MAX_EVIDENCE_PER_FINDING]:
            label = esc(item.get("description"), 300)
            if item.get("sensitive"):
                label += " (value masked)"
            block.append(Paragraph(label, styles["meta"]))
            if item.get("snippet"):
                block.append(Paragraph(esc(item["snippet"], MAX_SNIPPET_CHARS), styles["code"]))

        references = finding.get("references") or []
        if references:
            block.append(
                Paragraph("References: " + esc(" ".join(references), 400), styles["meta"])
            )
        block.append(HRFlowable(width="100%", thickness=0.3, color=LINE, spaceBefore=4, spaceAfter=4))
        story.append(KeepTogether(block))

    if len(findings) > MAX_FINDINGS_RENDERED:
        story.append(
            Paragraph(
                f"{len(findings) - MAX_FINDINGS_RENDERED} further findings are omitted "
                "from this PDF. Export the JSON report for the complete set.",
                styles["body"],
            )
        )
    return story


def _indicators(document: dict[str, Any], styles: dict) -> list[Any]:
    indicators = document.get("indicators", [])
    if not indicators:
        return []
    story = [
        Paragraph("Network indicators", styles["h2"]),
        Paragraph(
            "Extracted from application contents and classified by routing scope. "
            "These are observations, not evidence of malicious behaviour. DroidScope "
            "does not contact extracted destinations.",
            styles["body"],
        ),
    ]
    rows = [
        [
            Paragraph("<b>Type</b>", styles["cell"]),
            Paragraph("<b>Value</b>", styles["cell"]),
            Paragraph("<b>Scope</b>", styles["cell"]),
            Paragraph("<b>Count</b>", styles["cell"]),
        ]
    ]
    for indicator in indicators[:100]:
        rows.append(
            [
                Paragraph(esc(indicator.get("type")), styles["cell"]),
                Paragraph(esc(indicator.get("value"), 120), styles["cellmono"]),
                Paragraph(esc(indicator.get("scope")), styles["cell"]),
                Paragraph(esc(indicator.get("occurrences")), styles["cell"]),
            ]
        )
    story.append(_grid(rows, [20 * mm, None, 26 * mm, 16 * mm]))
    return story


def _appendix(document: dict[str, Any], styles: dict) -> list[Any]:
    report = document.get("report", {})
    scan = document.get("scan", {})
    application = document.get("application", {})
    environment = document.get("environment", {})

    versions = environment.get("tool_versions", {})
    rows = [
        ("Scan identifier", scan.get("id")),
        ("Scan status", scan.get("status")),
        ("Profile", scan.get("profile")),
        ("Started", scan.get("started_at")),
        ("Finished", scan.get("finished_at")),
        ("Duration", f"{scan.get('duration_seconds') or 0:.2f}s"),
        ("APK SHA-256", application.get("sha256")),
        ("Generated at", report.get("generated_at")),
        ("Generator", report.get("generator")),
        ("Secret redaction", "applied" if report.get("redaction_applied") else "disabled"),
        ("Rules loaded", environment.get("rules_loaded")),
        ("Tool versions", ", ".join(f"{k} {v}" for k, v in sorted(versions.items())) or "none recorded"),
        ("Tools unavailable", ", ".join(environment.get("tools_unavailable", [])) or "none"),
    ]
    host = environment.get("host", {})
    if host:
        rows.append(("Analysis host", f"{host.get('system')} {host.get('release')} {host.get('machine')}"))

    return [
        PageBreak(),
        Paragraph("Appendix: analysis metadata", styles["h2"]),
        _kv_table(rows, styles, mono_values=True),
        Spacer(1, 6 * mm),
        Paragraph(
            f"Report produced by {esc(report.get('generator'))} at "
            f"{esc(report.get('generated_at'))}. Reproduce this analysis with "
            f"droidscope analyze --profile {esc(scan.get('profile'))} against the APK "
            f"with SHA-256 {esc(application.get('sha256'))}.",
            styles["meta"],
        ),
    ]


def _grid(rows: list[list[Any]], widths: list[Any]) -> Table:
    table = Table(rows, colWidths=widths, hAlign="LEFT", repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("BACKGROUND", (0, 0), (-1, 0), SURFACE),
                ("LINEBELOW", (0, 0), (-1, -1), 0.3, LINE),
                ("BOX", (0, 0), (-1, -1), 0.4, LINE),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    return table
