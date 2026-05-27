from pathlib import Path
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    ListFlowable,
    ListItem,
    PageBreak,
    Paragraph,
    Preformatted,
    SimpleDocTemplate,
    Spacer,
)


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "Baloncore_roadmap.md"
OUTPUT = ROOT / "Baloncore_roadmap.pdf"


def make_styles():
    styles = getSampleStyleSheet()
    styles.add(
        ParagraphStyle(
            name="RoadmapTitle",
            parent=styles["Title"],
            fontName="Helvetica-Bold",
            fontSize=24,
            leading=30,
            textColor=colors.HexColor("#111827"),
            spaceAfter=18,
        )
    )
    styles.add(
        ParagraphStyle(
            name="RoadmapH2",
            parent=styles["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=16,
            leading=20,
            textColor=colors.HexColor("#1f2937"),
            spaceBefore=14,
            spaceAfter=8,
        )
    )
    styles.add(
        ParagraphStyle(
            name="RoadmapH3",
            parent=styles["Heading3"],
            fontName="Helvetica-Bold",
            fontSize=12,
            leading=15,
            textColor=colors.HexColor("#374151"),
            spaceBefore=10,
            spaceAfter=5,
        )
    )
    styles.add(
        ParagraphStyle(
            name="RoadmapBody",
            parent=styles["BodyText"],
            fontName="Helvetica",
            fontSize=9.5,
            leading=13,
            textColor=colors.HexColor("#111827"),
            spaceAfter=6,
        )
    )
    styles.add(
        ParagraphStyle(
            name="RoadmapBullet",
            parent=styles["BodyText"],
            fontName="Helvetica",
            fontSize=9.2,
            leading=12,
            leftIndent=8,
            textColor=colors.HexColor("#111827"),
        )
    )
    styles.add(
        ParagraphStyle(
            name="RoadmapCode",
            parent=styles["Code"],
            fontName="Courier",
            fontSize=8,
            leading=10,
            textColor=colors.HexColor("#111827"),
            backColor=colors.HexColor("#f3f4f6"),
            borderColor=colors.HexColor("#e5e7eb"),
            borderWidth=0.5,
            borderPadding=6,
            spaceBefore=4,
            spaceAfter=8,
        )
    )
    return styles


def inline_markup(text: str) -> str:
    text = escape(text)
    parts = text.split("**")
    if len(parts) > 1:
        rebuilt = []
        for index, part in enumerate(parts):
            if index % 2:
                rebuilt.append(f"<b>{part}</b>")
            else:
                rebuilt.append(part)
        text = "".join(rebuilt)
    return text


def flush_paragraph(lines, story, styles):
    if not lines:
        return
    text = " ".join(line.strip() for line in lines).strip()
    if text:
        story.append(Paragraph(inline_markup(text), styles["RoadmapBody"]))
    lines.clear()


def flush_bullets(items, story, styles):
    if not items:
        return
    flow_items = [
        ListItem(Paragraph(inline_markup(item), styles["RoadmapBullet"]), bulletColor=colors.HexColor("#111827"))
        for item in items
    ]
    story.append(ListFlowable(flow_items, bulletType="bullet", leftIndent=18))
    story.append(Spacer(1, 4))
    items.clear()


def build_story(markdown: str):
    styles = make_styles()
    story = []
    paragraph_lines = []
    bullet_items = []
    code_lines = []
    in_code = False

    for raw_line in markdown.splitlines():
        line = raw_line.rstrip()

        if line.startswith("```"):
            if in_code:
                story.append(Preformatted("\n".join(code_lines), styles["RoadmapCode"]))
                code_lines = []
                in_code = False
            else:
                flush_paragraph(paragraph_lines, story, styles)
                flush_bullets(bullet_items, story, styles)
                in_code = True
            continue

        if in_code:
            code_lines.append(line)
            continue

        if not line.strip():
            flush_paragraph(paragraph_lines, story, styles)
            flush_bullets(bullet_items, story, styles)
            continue

        if line.startswith("# "):
            flush_paragraph(paragraph_lines, story, styles)
            flush_bullets(bullet_items, story, styles)
            story.append(Paragraph(inline_markup(line[2:]), styles["RoadmapTitle"]))
            continue

        if line.startswith("## "):
            flush_paragraph(paragraph_lines, story, styles)
            flush_bullets(bullet_items, story, styles)
            heading = line[3:]
            if heading.startswith("Stage ") and story:
                story.append(PageBreak())
            story.append(Paragraph(inline_markup(heading), styles["RoadmapH2"]))
            continue

        if line.startswith("### "):
            flush_paragraph(paragraph_lines, story, styles)
            flush_bullets(bullet_items, story, styles)
            story.append(Paragraph(inline_markup(line[4:]), styles["RoadmapH3"]))
            continue

        if line.startswith("- "):
            flush_paragraph(paragraph_lines, story, styles)
            bullet_items.append(line[2:])
            continue

        if len(line) > 3 and line[0].isdigit() and ". " in line[:4]:
            flush_bullets(bullet_items, story, styles)
            paragraph_lines.append(line)
            continue

        flush_bullets(bullet_items, story, styles)
        paragraph_lines.append(line)

    flush_paragraph(paragraph_lines, story, styles)
    flush_bullets(bullet_items, story, styles)
    return story


def add_page_number(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(colors.HexColor("#6b7280"))
    canvas.drawRightString(7.5 * inch, 0.45 * inch, f"BALONCORE Roadmap | Page {doc.page}")
    canvas.restoreState()


def main():
    markdown = SOURCE.read_text(encoding="utf-8")
    doc = SimpleDocTemplate(
        str(OUTPUT),
        pagesize=LETTER,
        rightMargin=0.65 * inch,
        leftMargin=0.65 * inch,
        topMargin=0.65 * inch,
        bottomMargin=0.65 * inch,
        title="BALONCORE Roadmap",
        author="BALONCORE",
    )
    doc.build(build_story(markdown), onFirstPage=add_page_number, onLaterPages=add_page_number)
    print(OUTPUT)


if __name__ == "__main__":
    main()
