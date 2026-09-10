from __future__ import annotations

from io import BytesIO
from typing import Any, cast

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)
from reportlab.platypus.tableofcontents import TableOfContents

from stealthix.core.models import ScanResult
from stealthix.reporting.presentation import build_report_context


def render_pdf(result: ScanResult) -> bytes:
    """Render scan result as PDF with enhanced styling."""
    report = build_report_context(result)
    buffer = BytesIO()

    # Create document with page numbers
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=0.75 * inch,
        rightMargin=0.75 * inch,
        topMargin=0.75 * inch,
        bottomMargin=0.5 * inch,
    )

    # Custom styles
    styles = getSampleStyleSheet()
    heading = ParagraphStyle(
        "CustomHeading1",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=18,
        textColor=colors.HexColor("#1f2937"),
        spaceAfter=12,
    )
    subheading = ParagraphStyle(
        "CustomHeading2",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=14,
        textColor=colors.HexColor("#667eea"),
        spaceAfter=10,
    )
    body = ParagraphStyle(
        "CustomBody",
        parent=styles["BodyText"],
        fontName="Helvetica",
        fontSize=10,
        leading=12,
    )
    mono = ParagraphStyle("Mono", parent=body, fontName="Courier", fontSize=8, leading=10)

    # Build story
    story: list[Any] = [
        Paragraph("Stealthix Enterprise Report", heading),
        Paragraph(f"Target: {report['target']}", body),
        Paragraph(f"Generated: {report.get('generated_at') or ''}", body),
        Paragraph(
            f"Risk score: {report['executive_summary']['risk_score']} ({report['executive_summary']['risk_rating']}) | Highest CVSS: {report['scores']['highest']} | Average CVSS: {report['scores']['average']}",
            body,
        ),
        Spacer(1, 12),
        Paragraph("Executive Summary", subheading),
    ]

    # Executive summary table with improved styling
    summary_table = Table(
        [
            ["Metric", "Value"],
            ["Total findings", str(report["executive_summary"]["total_findings"])],
            ["Highest severity", report["executive_summary"]["highest_severity"]],
            ["Requests observed", str(report["attack_surface"]["request_count"])],
            ["Targets observed", str(report["attack_surface"]["target_count"])],
        ],
        colWidths=[2 * inch, 4 * inch],
    )
    summary_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#667eea")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, 0), 11),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d1d5db")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f9fafb")]),
            ]
        )
    )
    story.extend([summary_table, Spacer(1, 14), Paragraph("Findings", subheading)])

    # Findings with severity-colored badges
    if not report["findings"]:
        story.append(Paragraph("No findings were recorded.", body))
    else:
        for finding in report["findings"]:
            severity = finding.get("severity", "Info")
            severity_color = _get_severity_color(severity)
            story.append(Paragraph(f"<b>{finding['kind']}</b> — {finding['summary']}", body))
            story.append(Paragraph(f"Target: {finding['target']}", body))
            story.append(
                Paragraph(f"<font color='{severity_color}'>Severity: {severity}</font>", body)
            )
            story.append(
                Paragraph(
                    f"CVSS: {finding.get('cvss', 0):.1f} | Confidence: {finding.get('confidence', 'N/A')} ({finding.get('confidence_score', 0):.0%})",
                    body,
                )
            )
            story.append(
                Paragraph(
                    f"CWE: {finding['compliance']['cwe']['id']} | OWASP: {', '.join(item['id'] for item in finding['compliance']['owasp_top_10'])}",
                    body,
                )
            )
            story.append(
                Paragraph(
                    f"Remediation: {finding['remediation'][0] if finding['remediation'] else 'N/A'}",
                    body,
                )
            )
            if finding["evidence_pairs"]:
                pair = finding["evidence_pairs"][0]
                story.append(
                    Paragraph(
                        f"Request: {pair['request'].get('method')} {pair['request'].get('url')}",
                        mono,
                    )
                )
                response_line = f"Response: {pair['response'].get('status') or ''} {pair['response'].get('content_type') or ''}"
                story.append(Paragraph(response_line.strip(), mono))
                if pair["response"].get("body"):
                    story.append(Paragraph(pair["response"]["body"][:500], mono))
            story.append(Spacer(1, 10))

    # Reconnaissance section
    if report.get("reconnaissance"):
        story.append(PageBreak())
        story.append(Paragraph("Reconnaissance", subheading))
        recon = report["reconnaissance"]
        story.append(
            Paragraph(
                f"Technologies detected: {recon['summary']['tech_count']} | Endpoints discovered: {recon['summary']['endpoint_count']} | Elapsed: {recon['summary']['elapsed']:.2f}s",
                body,
            )
        )
        if recon["technologies"]:
            story.append(Spacer(1, 8))
            story.append(Paragraph("Detected Technologies", subheading))
            tech_data = [["Category", "Name", "Version", "Confidence"]]
            for tech in recon["technologies"]:
                tech_data.append(
                    [
                        tech["category"],
                        tech["name"],
                        tech.get("version") or "N/A",
                        f"{tech['confidence']:.1%}",
                    ]
                )
            tech_table = Table(tech_data, colWidths=[1.5 * inch, 2 * inch, 1 * inch, 1 * inch])
            tech_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#667eea")),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, 0), 10),
                        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d1d5db")),
                        (
                            "ROWBACKGROUNDS",
                            (0, 1),
                            (-1, -1),
                            [colors.white, colors.HexColor("#f9fafb")],
                        ),
                    ]
                )
            )
            story.append(tech_table)
        if recon["endpoints"]:
            story.append(Spacer(1, 8))
            story.append(Paragraph("Discovered Endpoints", subheading))
            endpoint_data = [["URL", "Status", "Category", "Confidence"]]
            for endpoint in recon["endpoints"][:10]:
                endpoint_data.append(
                    [
                        endpoint["url"],
                        str(endpoint["status_code"]),
                        endpoint["category"],
                        f"{endpoint['confidence']:.1%}",
                    ]
                )
            endpoint_table = Table(
                endpoint_data, colWidths=[3 * inch, 0.75 * inch, 1.5 * inch, 0.75 * inch]
            )
            endpoint_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#667eea")),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, 0), 10),
                        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d1d5db")),
                        (
                            "ROWBACKGROUNDS",
                            (0, 1),
                            (-1, -1),
                            [colors.white, colors.HexColor("#f9fafb")],
                        ),
                    ]
                )
            )
            story.append(endpoint_table)  # type: ignore[arg-type]
        story.append(Spacer(1, 12))

    # Timeline section
    if report["timeline"]:
        story.append(PageBreak())  # type: ignore[arg-type]
        story.append(Paragraph("Timeline", subheading))
        for event in report["timeline"]:
            story.append(
                Paragraph(
                    f"{event.get('timestamp') or ''} — <b>{event['phase']}</b>: {event['message']}",
                    body,
                )
            )

    doc.build(story)
    return buffer.getvalue()


def _get_severity_color(severity: str) -> str:
    """Get hex color for severity level."""
    colors_map = {
        "Critical": "#dc3545",
        "High": "#fd7e14",
        "Medium": "#ffc107",
        "Low": "#17a2b8",
        "Info": "#6c757d",
    }
    return colors_map.get(severity, "#6c757d")
