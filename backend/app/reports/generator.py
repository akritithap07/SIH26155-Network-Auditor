from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


REPORT_DIR = (
    Path(__file__).resolve().parents[2]
    / "data"
    / "reports"
)


def _safe_text(value: Any) -> str:
    if value is None:
        return "—"

    return str(value)


def _paragraph(
    text: Any,
    style: ParagraphStyle,
) -> Paragraph:
    escaped = (
        _safe_text(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("\n", "<br/>")
    )

    return Paragraph(
        escaped,
        style,
    )


def _build_styles():
    styles = getSampleStyleSheet()

    return {
        "title": ParagraphStyle(
            "ReportTitle",
            parent=styles["Title"],
            fontSize=22,
            leading=26,
            alignment=TA_CENTER,
            spaceAfter=10,
        ),
        "subtitle": ParagraphStyle(
            "ReportSubtitle",
            parent=styles["Normal"],
            fontSize=10,
            leading=14,
            alignment=TA_CENTER,
            textColor=colors.HexColor(
                "#6B7280"
            ),
            spaceAfter=18,
        ),
        "heading": ParagraphStyle(
            "ReportHeading",
            parent=styles["Heading2"],
            fontSize=15,
            leading=19,
            spaceBefore=10,
            spaceAfter=8,
        ),
        "subheading": ParagraphStyle(
            "ReportSubheading",
            parent=styles["Heading3"],
            fontSize=11,
            leading=15,
            spaceBefore=6,
            spaceAfter=5,
        ),
        "body": ParagraphStyle(
            "ReportBody",
            parent=styles["BodyText"],
            fontSize=9,
            leading=13,
            spaceAfter=5,
        ),
        "small": ParagraphStyle(
            "ReportSmall",
            parent=styles["BodyText"],
            fontSize=8,
            leading=11,
            textColor=colors.HexColor(
                "#4B5563"
            ),
        ),
        "code": ParagraphStyle(
            "ReportCode",
            parent=styles["BodyText"],
            fontName="Courier",
            fontSize=8,
            leading=11,
            backColor=colors.HexColor(
                "#F3F4F6"
            ),
            borderPadding=5,
            spaceAfter=5,
        ),
    }


def _make_summary_table(
    compliance: Dict[str, Any],
):
    summary = compliance.get(
        "summary",
        {},
    )

    data = [
        [
            "PASS",
            "FAIL",
            "NOT ASSESSED",
            "POSTURE",
        ],
        [
            _safe_text(
                summary.get("PASS", 0)
            ),
            _safe_text(
                summary.get("FAIL", 0)
            ),
            _safe_text(
                summary.get(
                    "NOT_ASSESSED",
                    0,
                )
            ),
            _safe_text(
                summary.get(
                    "posture_score",
                    "—",
                )
            ),
        ],
    ]

    table = Table(
        data,
        colWidths=[
            38 * mm,
            38 * mm,
            45 * mm,
            38 * mm,
        ],
    )

    table.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.HexColor(
                        "#111827"
                    ),
                ),
                (
                    "TEXTCOLOR",
                    (0, 0),
                    (-1, 0),
                    colors.white,
                ),
                (
                    "FONTNAME",
                    (0, 0),
                    (-1, 0),
                    "Helvetica-Bold",
                ),
                (
                    "FONTNAME",
                    (0, 1),
                    (-1, 1),
                    "Helvetica-Bold",
                ),
                (
                    "ALIGN",
                    (0, 0),
                    (-1, -1),
                    "CENTER",
                ),
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "MIDDLE",
                ),
                (
                    "BOX",
                    (0, 0),
                    (-1, -1),
                    0.5,
                    colors.HexColor(
                        "#D1D5DB"
                    ),
                ),
                (
                    "INNERGRID",
                    (0, 0),
                    (-1, -1),
                    0.5,
                    colors.HexColor(
                        "#E5E7EB"
                    ),
                ),
                (
                    "BACKGROUND",
                    (0, 1),
                    (-1, 1),
                    colors.HexColor(
                        "#F9FAFB"
                    ),
                ),
                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    8,
                ),
                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    8,
                ),
            ]
        )
    )

    return table


def _make_finding_table(
    findings: List[Dict[str, Any]],
    styles: Dict[str, ParagraphStyle],
):
    rows = [
        [
            "ID",
            "Finding",
            "Status",
            "Severity",
            "Evidence",
        ]
    ]

    for finding in findings:
        rows.append(
            [
                _paragraph(
                    finding.get("id"),
                    styles["small"],
                ),
                _paragraph(
                    finding.get("name"),
                    styles["small"],
                ),
                _paragraph(
                    finding.get("status"),
                    styles["small"],
                ),
                _paragraph(
                    finding.get("severity"),
                    styles["small"],
                ),
                _paragraph(
                    finding.get("evidence"),
                    styles["small"],
                ),
            ]
        )

    table = Table(
        rows,
        colWidths=[
            24 * mm,
            42 * mm,
            30 * mm,
            25 * mm,
            59 * mm,
        ],
        repeatRows=1,
    )

    table.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.HexColor(
                        "#111827"
                    ),
                ),
                (
                    "TEXTCOLOR",
                    (0, 0),
                    (-1, 0),
                    colors.white,
                ),
                (
                    "FONTNAME",
                    (0, 0),
                    (-1, 0),
                    "Helvetica-Bold",
                ),
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.4,
                    colors.HexColor(
                        "#D1D5DB"
                    ),
                ),
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP",
                ),
                (
                    "BACKGROUND",
                    (0, 1),
                    (-1, -1),
                    colors.white,
                ),
                (
                    "LEFTPADDING",
                    (0, 0),
                    (-1, -1),
                    5,
                ),
                (
                    "RIGHTPADDING",
                    (0, 0),
                    (-1, -1),
                    5,
                ),
                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    5,
                ),
                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    5,
                ),
            ]
        )
    )

    return table


def _make_shadow_table(
    issues: List[Dict[str, Any]],
    styles: Dict[str, ParagraphStyle],
):
    rows = [
        [
            "Type",
            "Severity",
            "Shadowing Rule",
            "Shadowed Rule",
            "Remediation",
        ]
    ]

    for issue in issues:
        rows.append(
            [
                _paragraph(
                    issue.get("type"),
                    styles["small"],
                ),
                _paragraph(
                    issue.get("severity"),
                    styles["small"],
                ),
                _paragraph(
                    issue.get(
                        "shadowing_rule"
                    ),
                    styles["small"],
                ),
                _paragraph(
                    issue.get(
                        "shadowed_rule"
                    ),
                    styles["small"],
                ),
                _paragraph(
                    issue.get(
                        "remediation"
                    ),
                    styles["small"],
                ),
            ]
        )

    table = Table(
        rows,
        colWidths=[
            30 * mm,
            25 * mm,
            40 * mm,
            40 * mm,
            45 * mm,
        ],
        repeatRows=1,
    )

    table.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.HexColor(
                        "#111827"
                    ),
                ),
                (
                    "TEXTCOLOR",
                    (0, 0),
                    (-1, 0),
                    colors.white,
                ),
                (
                    "FONTNAME",
                    (0, 0),
                    (-1, 0),
                    "Helvetica-Bold",
                ),
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.4,
                    colors.HexColor(
                        "#D1D5DB"
                    ),
                ),
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP",
                ),
                (
                    "LEFTPADDING",
                    (0, 0),
                    (-1, -1),
                    5,
                ),
                (
                    "RIGHTPADDING",
                    (0, 0),
                    (-1, -1),
                    5,
                ),
                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    5,
                ),
                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    5,
                ),
            ]
        )
    )

    return table


def generate_audit_report(
    audit_result: Dict[str, Any],
) -> Path:
    REPORT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    filename = str(
        audit_result.get(
            "filename",
            "configuration",
        )
    )

    base_name = (
        Path(filename).stem
        or "configuration"
    )

    timestamp = datetime.now(
        timezone.utc
    ).strftime(
        "%Y%m%d_%H%M%S"
    )

    output_path = (
        REPORT_DIR
        / f"{base_name}_audit_{timestamp}.pdf"
    )

    styles = _build_styles()

    document = SimpleDocTemplate(
        str(output_path),
        pagesize=A4,
        rightMargin=15 * mm,
        leftMargin=15 * mm,
        topMargin=15 * mm,
        bottomMargin=15 * mm,
        title=(
            f"Network Security Audit - "
            f"{base_name}"
        ),
        author=(
            "SIH26155 Network Security "
            "Compliance Engine"
        ),
    )

    story = []

    detection = audit_result.get(
        "detection",
        {},
    )

    vendor = detection.get(
        "vendor",
        "unknown",
    )

    story.append(
        _paragraph(
            "Network Security Compliance Audit",
            styles["title"],
        )
    )

    story.append(
        _paragraph(
            "SIH26155 Network Security Compliance Engine",
            styles["subtitle"],
        )
    )

    metadata_rows = [
        [
            "Configuration",
            _safe_text(filename),
        ],
        [
            "Vendor",
            _safe_text(vendor),
        ],
        [
            "Detection confidence",
            _safe_text(
                detection.get(
                    "confidence",
                    "—",
                )
            ),
        ],
        [
            "Audit status",
            _safe_text(
                audit_result.get(
                    "status",
                    "—",
                )
            ),
        ],
    ]

    metadata_table = Table(
        metadata_rows,
        colWidths=[
            50 * mm,
            125 * mm,
        ],
    )

    metadata_table.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (0, -1),
                    colors.HexColor(
                        "#F3F4F6"
                    ),
                ),
                (
                    "FONTNAME",
                    (0, 0),
                    (0, -1),
                    "Helvetica-Bold",
                ),
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.4,
                    colors.HexColor(
                        "#D1D5DB"
                    ),
                ),
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP",
                ),
                (
                    "LEFTPADDING",
                    (0, 0),
                    (-1, -1),
                    7,
                ),
                (
                    "RIGHTPADDING",
                    (0, 0),
                    (-1, -1),
                    7,
                ),
                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    7,
                ),
                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    7,
                ),
            ]
        )
    )

    story.append(metadata_table)
    story.append(Spacer(1, 8))

    compliance = audit_result.get(
        "compliance"
    )

    if compliance:
        story.append(
            _paragraph(
                "1. Compliance Summary",
                styles["heading"],
            )
        )

        story.append(
            _make_summary_table(
                compliance
            )
        )

        story.append(Spacer(1, 10))

        findings = compliance.get(
            "findings",
            [],
        )

        if findings:
            story.append(
                _paragraph(
                    "Compliance Findings",
                    styles["subheading"],
                )
            )

            story.append(
                _make_finding_table(
                    findings,
                    styles,
                )
            )

    shadow_rules = audit_result.get(
        "shadow_rules"
    )

    if shadow_rules is not None:
        story.append(
            PageBreak()
        )

        story.append(
            _paragraph(
                "2. Shadow Rule Detection",
                styles["heading"],
            )
        )

        summary = shadow_rules.get(
            "summary",
            {},
        )

        shadow_summary = Table(
            [
                [
                    "Critical",
                    "Medium",
                    "Total",
                ],
                [
                    _safe_text(
                        summary.get(
                            "critical",
                            0,
                        )
                    ),
                    _safe_text(
                        summary.get(
                            "medium",
                            0,
                        )
                    ),
                    _safe_text(
                        summary.get(
                            "total",
                            0,
                        )
                    ),
                ],
            ],
            colWidths=[
                45 * mm,
                45 * mm,
                45 * mm,
            ],
        )

        shadow_summary.setStyle(
            TableStyle(
                [
                    (
                        "BACKGROUND",
                        (0, 0),
                        (-1, 0),
                        colors.HexColor(
                            "#111827"
                        ),
                    ),
                    (
                        "TEXTCOLOR",
                        (0, 0),
                        (-1, 0),
                        colors.white,
                    ),
                    (
                        "FONTNAME",
                        (0, 0),
                        (-1, 0),
                        "Helvetica-Bold",
                    ),
                    (
                        "ALIGN",
                        (0, 0),
                        (-1, -1),
                        "CENTER",
                    ),
                    (
                        "GRID",
                        (0, 0),
                        (-1, -1),
                        0.4,
                        colors.HexColor(
                            "#D1D5DB"
                        ),
                    ),
                    (
                        "TOPPADDING",
                        (0, 0),
                        (-1, -1),
                        8,
                    ),
                    (
                        "BOTTOMPADDING",
                        (0, 0),
                        (-1, -1),
                        8,
                    ),
                ]
            )
        )

        story.append(
            shadow_summary
        )
        story.append(Spacer(1, 10))

        shadow_issues = shadow_rules.get(
            "issues",
            [],
        )

        if shadow_issues:
            story.append(
                _make_shadow_table(
                    shadow_issues,
                    styles,
                )
            )
        else:
            story.append(
                _paragraph(
                    "No shadowed or redundant "
                    "firewall rules were detected.",
                    styles["body"],
                )
            )

    ai_assistance = audit_result.get(
        "ai_assistance"
    )

    if ai_assistance is not None:
        story.append(
            PageBreak()
        )

        story.append(
            _paragraph(
                "3. AI Assistance",
                styles["heading"],
            )
        )

        story.append(
            _paragraph(
                "AI suggestions are advisory only "
                "and do not change PASS, FAIL, or "
                "NOT_ASSESSED compliance decisions.",
                styles["body"],
            )
        )

        entries = ai_assistance.get(
            "entries",
            [],
        )

        if not entries:
            story.append(
                _paragraph(
                    "No unrecognized configuration "
                    "entries required AI assistance.",
                    styles["body"],
                )
            )
        else:
            for entry in entries:
                story.append(
                    _paragraph(
                        "Unknown configuration entry",
                        styles["subheading"],
                    )
                )

                story.append(
                    _paragraph(
                        entry.get(
                            "text"
                        ),
                        styles["code"],
                    )
                )

                if entry.get("context"):
                    story.append(
                        _paragraph(
                            (
                                "Context: "
                                f"{entry['context']}"
                            ),
                            styles["small"],
                        )
                    )

                suggestions = entry.get(
                    "suggestions",
                    [],
                )

                for suggestion in suggestions:
                    block = [
                        _paragraph(
                            (
                                f"{suggestion.get('control_id')} "
                                f"— "
                                f"{suggestion.get('target_key')}"
                            ),
                            styles["subheading"],
                        ),
                        _paragraph(
                            (
                                f"Score: "
                                f"{suggestion.get('score', '—')} | "
                                f"Confidence: "
                                f"{suggestion.get('confidence_band', '—')} | "
                                f"Source: "
                                f"{suggestion.get('match_source', '—')} | "
                                f"Learned: "
                                f"{suggestion.get('learned', False)}"
                            ),
                            styles["small"],
                        ),
                        _paragraph(
                            suggestion.get(
                                "description",
                                "—",
                            ),
                            styles["body"],
                        ),
                    ]

                    story.append(
                        KeepTogether(block)
                    )

    story.append(Spacer(1, 10))

    story.append(
        _paragraph(
            (
                "Generated by SIH26155 Network "
                "Security Compliance Engine."
            ),
            styles["small"],
        )
    )

    document.build(story)

    return output_path