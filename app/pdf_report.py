"""
pdf_report.py — Génère un rapport PDF du scan ARGUS Security.

Approche simplifiée : multi_cell pleine largeur partout pour éviter les
bugs de positionnement de fpdf2. Le PDF reprend les éléments-clé du
rapport sans révéler aucun nom d'outil interne.
"""

from io import BytesIO
from fpdf import FPDF

# Palette ARGUS adaptée pour impression
COLOR_PRIMARY = (10, 14, 26)
COLOR_TEXT = (40, 50, 70)
COLOR_DIM = (110, 120, 140)
COLOR_CYAN = (0, 167, 217)
COLOR_VIOLET = (140, 80, 220)
COLOR_GREEN = (0, 180, 100)
COLOR_RED = (220, 60, 90)
COLOR_ORANGE = (230, 130, 50)
COLOR_YELLOW = (200, 160, 30)

PAGE_WIDTH = 180   # A4 - margins
LINE_W = 180       # full width


def _grade_color(grade: str):
    return {
        "A": COLOR_GREEN, "B": COLOR_CYAN, "C": COLOR_YELLOW,
        "D": COLOR_ORANGE, "F": COLOR_RED,
    }.get(grade, COLOR_DIM)


def _severity_color(sev: str):
    return {
        "critical": COLOR_RED, "high": COLOR_ORANGE,
        "medium": COLOR_YELLOW, "low": COLOR_CYAN,
    }.get((sev or "").lower(), COLOR_DIM)


def _safe(text):
    """Convertit en latin-1 compatible fpdf2 core fonts."""
    if text is None:
        return ""
    return str(text).encode("latin-1", "replace").decode("latin-1")


class ArgusReport(FPDF):
    """PDF avec en-tête/pied de page ARGUS."""

    def __init__(self, scan_id: int):
        super().__init__(orientation="P", unit="mm", format="A4")
        self.scan_id = scan_id
        self.set_auto_page_break(auto=True, margin=18)
        self.set_margins(left=15, top=15, right=15)

    def header(self):
        self.set_font("Helvetica", "B", 14)
        self.set_text_color(*COLOR_CYAN)
        self.cell(0, 8, "ARGUS Security", new_x="LMARGIN", new_y="NEXT")
        self.set_y(15)
        self.set_font("Helvetica", "", 9)
        self.set_text_color(*COLOR_DIM)
        self.cell(0, 8, f"Rapport #{self.scan_id}", align="R", new_x="LMARGIN", new_y="NEXT")
        self.set_draw_color(*COLOR_DIM)
        self.set_line_width(0.2)
        self.line(15, 25, 195, 25)
        self.ln(6)

    def footer(self):
        self.set_y(-12)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(*COLOR_DIM)
        self.cell(0, 5, f"ARGUS by Exasys - Confidentiel - Page {self.page_no()}/{{nb}}",
                  align="C", new_x="LMARGIN", new_y="NEXT")

    def heading(self, text: str, color=None, size=22):
        self.set_font("Helvetica", "B", size)
        self.set_text_color(*(color or COLOR_CYAN))
        self.multi_cell(LINE_W, size * 0.5, _safe(text), wrapmode="CHAR")
        self.ln(2)

    def section(self, text: str, color=None):
        self.ln(3)
        self.set_font("Helvetica", "B", 12)
        self.set_text_color(*(color or COLOR_VIOLET))
        self.multi_cell(LINE_W, 7, _safe("> " + text.upper()), wrapmode="CHAR")
        self.ln(1)

    def para(self, text: str, color=None, size=10, bold=False):
        self.set_font("Helvetica", "B" if bold else "", size)
        self.set_text_color(*(color or COLOR_TEXT))
        self.multi_cell(LINE_W, size * 0.55, _safe(text), wrapmode="CHAR")
        self.ln(1)


def generate_pdf(scan, assets, vulns, tls_findings) -> bytes:
    """Génère un PDF complet du rapport scan."""
    pdf = ArgusReport(scan_id=scan.id)
    pdf.alias_nb_pages()
    pdf.add_page()

    # ── EN-TÊTE DOMAINE ──────────────────────────────────────────────
    pdf.heading(scan.domain)
    started = scan.started_at.strftime("%d/%m/%Y a %H:%M") if scan.started_at else "-"
    pdf.para(f"Scan realise le {started}", color=COLOR_DIM, size=9)
    pdf.ln(3)

    # ── SCORE DE RISQUE ──────────────────────────────────────────────
    pdf.section("Argus Risk Score")

    grade = scan.risk_grade or "?"
    score = scan.risk_score or 0
    grade_color = _grade_color(grade)

    pdf.set_font("Helvetica", "B", 28)
    pdf.set_text_color(*grade_color)
    pdf.multi_cell(LINE_W, 14, _safe(f"{grade}  -  {score}/100"), wrapmode="CHAR")
    pdf.ln(2)

    grade_desc = {
        "A": "Excellent. Posture de securite exemplaire - peu d'angles d'attaque exploitables.",
        "B": "Correct. Quelques points faibles a corriger, rien d'urgent.",
        "C": "Moyen. Action recommandee a court terme.",
        "D": "Mauvais. Action urgente necessaire.",
        "F": "Critique. Votre exposition est dangereuse - corrigez immediatement.",
    }
    pdf.para(grade_desc.get(grade, ""), color=COLOR_DIM)

    # Breakdown
    if scan.risk_breakdown:
        pdf.ln(2)
        pdf.para("Detail du calcul :", bold=True, size=9, color=COLOR_TEXT)
        for item in scan.risk_breakdown[:10]:
            label = item.get("label", "")
            delta = item.get("delta", 0)
            reason = item.get("reason", "")
            color = COLOR_RED if delta < 0 else COLOR_GREEN
            line = f"  {delta:+d} pts  -  {label}"
            pdf.para(line, bold=True, size=9, color=color)
            pdf.para(f"      {reason}", size=8, color=COLOR_TEXT)

    # ── CHIFFRES CLES ────────────────────────────────────────────────
    pdf.section("Chiffres cles")
    rows = [
        ("Actifs decouverts", scan.assets_count or 0, COLOR_TEXT),
        ("Actifs en ligne (HTTP)", scan.alive_count or 0, COLOR_GREEN),
        ("Vulnerabilites detectees", scan.vulns_count or 0,
         COLOR_VIOLET if scan.vulns_count else COLOR_DIM),
        ("Critiques (P1)", scan.critical_count or 0,
         COLOR_RED if scan.critical_count else COLOR_DIM),
        ("Elevees (P2)", scan.high_count or 0,
         COLOR_ORANGE if scan.high_count else COLOR_DIM),
    ]
    if scan.kev_count:
        rows.append(("Exploitees activement (KEV)", scan.kev_count, COLOR_RED))

    for key, value, color in rows:
        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(*COLOR_DIM)
        line = f"{key:.<40} "
        pdf.multi_cell(LINE_W, 6, _safe(line + str(value)), wrapmode="CHAR")

    # ── ANALYSE EXECUTIVE (brief IA) ─────────────────────────────────
    if scan.ai_summary:
        pdf.section("Analyse Argus Security")
        # Clean markdown
        import re
        clean = scan.ai_summary
        clean = re.sub(r"\*\*(.+?)\*\*", r"\1", clean)
        clean = re.sub(r"^#{1,3}\s+", "", clean, flags=re.MULTILINE)
        clean = re.sub(r"^\s*---+\s*$", "", clean, flags=re.MULTILINE)
        clean = re.sub(r"\*(.+?)\*", r"\1", clean)
        # Split en paragraphes
        for para in [p.strip() for p in clean.split("\n\n") if p.strip()]:
            pdf.para(para)

    # ── SECURITE EMAIL & DNS ─────────────────────────────────────────
    pdf.section("Securite Email & DNS")
    spf = scan.spf or {}
    dmarc = scan.dmarc or {}
    dkim = scan.dkim or {}

    items = [
        ("SPF", spf.get("present"), "Present" if spf.get("present") else "Absent - spoofing facilite"),
        ("DMARC", dmarc.get("present"), "Present" if dmarc.get("present") else "Absent - phishing au nom du domaine non bloque"),
        ("DKIM", dkim.get("present"), "Detecte" if dkim.get("present") else "Non detecte"),
    ]
    for key, ok, value in items:
        color = COLOR_GREEN if ok else COLOR_RED
        pdf.set_font("Helvetica", "B", 10)
        pdf.set_text_color(*color)
        pdf.multi_cell(LINE_W, 6, _safe(f"{key}: {value}"), wrapmode="CHAR")

    # ── VULNERABILITES (top 20) ──────────────────────────────────────
    if vulns:
        pdf.add_page()
        pdf.section(f"Vulnerabilites detectees ({len(vulns)})")
        for v in vulns[:20]:
            sev = (v.severity or "info").lower()
            name = v.name or v.template_id or "?"
            pdf.set_font("Helvetica", "B", 9)
            pdf.set_text_color(*_severity_color(sev))
            pdf.multi_cell(LINE_W, 5, _safe(f"[{sev.upper()}] {name}"), wrapmode="CHAR")

            pdf.set_font("Helvetica", "", 8)
            pdf.set_text_color(*COLOR_DIM)
            line2 = f"   URL : {v.matched_url or '-'}"
            if v.cve_id:
                line2 += f"   CVE : {v.cve_id}"
            pdf.multi_cell(LINE_W, 5, _safe(line2), wrapmode="CHAR")
            pdf.ln(1)

        if len(vulns) > 20:
            pdf.set_font("Helvetica", "I", 9)
            pdf.set_text_color(*COLOR_DIM)
            pdf.multi_cell(LINE_W, 6, _safe(
                f"... {len(vulns) - 20} vulnerabilites supplementaires non affichees."
            ), wrapmode="CHAR")

    # ── ACTIFS IDENTIFIES (top 50) ───────────────────────────────────
    if assets:
        pdf.add_page()
        pdf.section(f"Actifs identifies ({len(assets)})")
        pdf.set_font("Helvetica", "", 8)
        pdf.set_text_color(*COLOR_TEXT)
        for a in assets[:50]:
            url = a.url or ""
            status = a.status_code or 0
            tech = ", ".join((a.tech or [])[:3]) if a.tech else ""
            line = f"  - {url}"
            if status:
                line += f"  [{status}]"
            if tech:
                line += f"  -  {tech}"
            pdf.multi_cell(LINE_W, 4.5, _safe(line), wrapmode="CHAR")

        if len(assets) > 50:
            pdf.set_font("Helvetica", "I", 9)
            pdf.set_text_color(*COLOR_DIM)
            pdf.ln(2)
            pdf.multi_cell(LINE_W, 6, _safe(
                f"... {len(assets) - 50} actifs supplementaires non affiches."
            ), wrapmode="CHAR")

    # ── FOOTER LEGAL ─────────────────────────────────────────────────
    pdf.ln(6)
    pdf.set_font("Helvetica", "I", 8)
    pdf.set_text_color(*COLOR_DIM)
    pdf.multi_cell(
        LINE_W, 4,
        _safe(
            "Ce rapport est confidentiel et destine exclusivement au proprietaire du domaine "
            "scanne. Les findings refletent l'etat de l'exposition publique au moment du scan. "
            "Une re-evaluation reguliere est recommandee."
        ),
        wrapmode="CHAR",
    )

    pdf_bytes = pdf.output(dest="S")
    if isinstance(pdf_bytes, str):
        pdf_bytes = pdf_bytes.encode("latin-1")
    elif isinstance(pdf_bytes, bytearray):
        pdf_bytes = bytes(pdf_bytes)
    return pdf_bytes
