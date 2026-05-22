"""
pdf_report.py — Rapport ARGUS Security en PDF (design pro).

Refonte complète 2026-05-21 avec :
- Vraie typographie Unicode (DejaVu Sans Regular/Bold/Italic)
- Header bandeau sombre avec logo radar dessiné en vector
- Score circle visuellement marquant
- 6 KPI cards en ligne
- Sections avec backgrounds colorés
- Tableaux propres avec wrapping intelligent
- Footer pro avec branding
"""

from io import BytesIO
from pathlib import Path
import re
from fpdf import FPDF

# Chemin vers les fonts DejaVu (embedded dans app/static/fonts/)
FONTS_DIR = Path(__file__).parent / "static" / "fonts"
FONT_REG = str(FONTS_DIR / "DejaVuSans.ttf")
FONT_BOLD = str(FONTS_DIR / "DejaVuSans-Bold.ttf")
FONT_ITAL = str(FONTS_DIR / "DejaVuSans-Oblique.ttf")

# ── Palette (cohérente avec la brand web) ──────────────────────
COL_BG_DARK    = (10, 14, 26)      # #0a0e1a noir ARGUS
COL_TEXT_DARK  = (26, 31, 46)      # body
COL_TEXT_DIM   = (110, 123, 140)   # secondary
COL_TEXT_FAINT = (170, 180, 195)   # very dim
COL_BG_CARD    = (248, 250, 252)   # bg cards
COL_BG_VIOLET  = (245, 240, 255)   # bg analyse
COL_DIVIDER    = (228, 232, 240)

COL_CYAN       = (0, 167, 217)     # primary
COL_VIOLET     = (140, 80, 220)    # accent / AI
COL_GREEN      = (0, 180, 100)     # OK / grade A
COL_YELLOW     = (224, 160, 30)    # warning / grade C
COL_ORANGE     = (230, 130, 50)    # high / grade D
COL_RED        = (220, 60, 90)     # critical / grade F
COL_WHITE      = (255, 255, 255)

GRADE_COLORS = {
    "A": COL_GREEN,
    "B": COL_CYAN,
    "C": COL_YELLOW,
    "D": COL_ORANGE,
    "F": COL_RED,
}

GRADE_LABELS = {
    "A": "Excellent",
    "B": "Correct",
    "C": "Moyen",
    "D": "Mauvais",
    "F": "Critique",
}

GRADE_DESCRIPTIONS = {
    "A": "Posture de sécurité exemplaire — peu d'angles d'attaque exploitables.",
    "B": "Quelques points faibles à corriger, rien d'urgent.",
    "C": "Action recommandée à court terme.",
    "D": "Action urgente nécessaire — vulnérabilités exploitables présentes.",
    "F": "Votre exposition est critique. Corrigez sans attendre.",
}


def _severity_color(sev: str):
    return {
        "critical": COL_RED,
        "high": COL_ORANGE,
        "medium": COL_YELLOW,
        "low": COL_CYAN,
    }.get((sev or "").lower(), COL_TEXT_DIM)


def _clean_text(text: str) -> str:
    """Nettoie le markdown de l'analyse IA pour le PDF."""
    if not text:
        return ""
    t = text
    t = re.sub(r"\*\*(.+?)\*\*", r"\1", t)
    t = re.sub(r"^#{1,3}\s+", "", t, flags=re.MULTILINE)
    t = re.sub(r"^\s*---+\s*$", "", t, flags=re.MULTILINE)
    t = re.sub(r"\*(.+?)\*", r"\1", t)
    t = re.sub(r"\n{3,}", "\n\n", t)
    return t.strip()


def _truncate(text: str, max_chars: int) -> str:
    """Tronque proprement avec ellipsis."""
    if not text:
        return ""
    if len(text) <= max_chars:
        return text
    return text[:max_chars - 1] + "…"


class ArgusReport(FPDF):
    """PDF ARGUS — design pro avec header sombre + sections cards."""

    def __init__(self, scan):
        super().__init__(orientation="P", unit="mm", format="A4")
        self.scan = scan
        self.set_auto_page_break(auto=True, margin=20)
        self.set_margins(left=15, top=15, right=15)
        # Fonts Unicode
        self.add_font("dv", "", FONT_REG)
        self.add_font("dv", "B", FONT_BOLD)
        self.add_font("dv", "I", FONT_ITAL)

    # ── Header / Footer ────────────────────────────────────────

    def header(self):
        # Bandeau noir 18mm sur toute la largeur
        self.set_fill_color(*COL_BG_DARK)
        self.rect(0, 0, 210, 18, style="F")

        # Logo radar dessiné en vector (cercles + crosshair)
        cx, cy = 22, 9
        self.set_draw_color(*COL_CYAN)
        self.set_line_width(0.6)
        self.circle(cx, cy, 5.5, style="D")
        self.circle(cx, cy, 3.0, style="D")
        # centre violet
        self.set_fill_color(*COL_VIOLET)
        self.circle(cx, cy, 1.2, style="F")
        # crosshair
        self.set_line_width(0.7)
        self.line(cx, cy - 6.5, cx, cy - 4.5)
        self.line(cx, cy + 4.5, cx, cy + 6.5)
        self.line(cx - 6.5, cy, cx - 4.5, cy)
        self.line(cx + 4.5, cy, cx + 6.5, cy)

        # Texte brand
        self.set_font("dv", "B", 12)
        self.set_text_color(*COL_CYAN)
        self.set_xy(30, 5.5)
        self.cell(40, 6, "ARGUS")
        self.set_font("dv", "", 9)
        self.set_text_color(*COL_TEXT_FAINT)
        self.set_xy(46, 6.2)
        self.cell(40, 5, "SECURITY")

        # Rapport # à droite
        self.set_font("dv", "", 9)
        self.set_text_color(*COL_TEXT_FAINT)
        self.set_xy(150, 6.5)
        self.cell(50, 5, f"Rapport d'analyse · #{self.scan.id}", align="R")

        # Espace après header
        self.set_y(25)
        self.set_text_color(*COL_TEXT_DARK)

    def footer(self):
        self.set_y(-14)
        # Ligne décorative
        self.set_draw_color(*COL_DIVIDER)
        self.set_line_width(0.2)
        self.line(15, self.get_y(), 195, self.get_y())
        self.ln(2)
        # Texte footer
        self.set_font("dv", "I", 8)
        self.set_text_color(*COL_TEXT_DIM)
        self.cell(90, 4, "ARGUS Security · Document confidentiel")
        self.cell(90, 4, f"Page {self.page_no()}/{{nb}}", align="R")

    # ── Primitives ─────────────────────────────────────────────

    def colored_rect(self, x, y, w, h, fill, radius=2):
        """Rectangle arrondi rempli."""
        self.set_fill_color(*fill)
        self.rect(x, y, w, h, style="F", round_corners=True if radius else False,
                  corner_radius=radius if radius else 0)

    def section_title(self, text, color=None):
        """Titre de section avec petit accent coloré à gauche."""
        self.ln(4)
        y = self.get_y()
        # Petite barre verticale colorée
        self.set_fill_color(*(color or COL_VIOLET))
        self.rect(15, y + 1, 1.2, 6, style="F")
        # Titre
        self.set_xy(18.5, y - 0.5)
        self.set_font("dv", "B", 13)
        self.set_text_color(*COL_TEXT_DARK)
        self.cell(180, 8, text)
        self.ln(11)

    def text_paragraph(self, text, size=10, color=None, italic=False):
        self.set_font("dv", "I" if italic else "", size)
        self.set_text_color(*(color or COL_TEXT_DARK))
        self.multi_cell(180, size * 0.55, text, wrapmode="CHAR")
        self.ln(1)

    def card_box(self, height, fill=COL_BG_CARD, border=None):
        """Démarre une "card" : dessine le fond + return la y de départ pour écrire dedans."""
        y_start = self.get_y()
        self.set_fill_color(*fill)
        self.rect(15, y_start, 180, height, style="F", round_corners=True, corner_radius=3)
        if border:
            self.set_draw_color(*border)
            self.set_line_width(0.3)
            self.rect(15, y_start, 180, height, style="D", round_corners=True, corner_radius=3)
        return y_start


def generate_pdf(scan, assets, vulns, tls_findings) -> bytes:
    """Génère le PDF ARGUS du scan."""
    pdf = ArgusReport(scan)
    pdf.alias_nb_pages()
    pdf.add_page()

    # ════════════════════════════════════════════════════════════
    # PAGE 1 — COUVERTURE & SYNTHÈSE
    # ════════════════════════════════════════════════════════════

    # ── Domaine en gros + date ──
    pdf.set_font("dv", "B", 32)
    pdf.set_text_color(*COL_CYAN)
    pdf.cell(0, 14, scan.domain, new_x="LMARGIN", new_y="NEXT")

    pdf.set_font("dv", "", 10)
    pdf.set_text_color(*COL_TEXT_DIM)
    started = scan.started_at.strftime("%d/%m/%Y à %H:%M") if scan.started_at else "—"
    pdf.cell(0, 5, f"Scan réalisé le {started}", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(7)

    # ── Score card (gros bloc avec cercle + description) ──
    grade = scan.risk_grade or "?"
    score = scan.risk_score or 0
    grade_color = GRADE_COLORS.get(grade, COL_TEXT_DIM)
    grade_label = GRADE_LABELS.get(grade, "—")
    grade_desc = GRADE_DESCRIPTIONS.get(grade, "")

    card_y = pdf.get_y()
    card_h = 48
    pdf.card_box(card_h, fill=COL_BG_CARD)

    # Cercle de score à gauche
    cx, cy = 35, card_y + card_h / 2
    radius = 17
    # Cercle de fond (plus pâle)
    r, g, b = grade_color
    pdf.set_fill_color(r, g, b)
    pdf.set_draw_color(r, g, b)
    pdf.set_line_width(2)
    pdf.circle(cx, cy, radius, style="D")
    # Lettre grade au centre
    pdf.set_font("dv", "B", 30)
    pdf.set_text_color(*grade_color)
    text_w = pdf.get_string_width(grade)
    pdf.set_xy(cx - text_w / 2, cy - 9)
    pdf.cell(text_w, 14, grade)

    # Score / 100 à droite du cercle (mais en haut)
    pdf.set_xy(60, card_y + 7)
    pdf.set_font("dv", "B", 24)
    pdf.set_text_color(*grade_color)
    pdf.cell(35, 9, f"{score}")
    pdf.set_font("dv", "", 12)
    pdf.set_text_color(*COL_TEXT_DIM)
    pdf.cell(20, 9, "/100")

    # Label du grade
    pdf.set_xy(60, card_y + 18)
    pdf.set_font("dv", "B", 11)
    pdf.set_text_color(*COL_TEXT_DARK)
    pdf.cell(80, 5, f"ARGUS Risk Score · {grade_label}")

    # Description grade
    pdf.set_xy(60, card_y + 25)
    pdf.set_font("dv", "", 10)
    pdf.set_text_color(*COL_TEXT_DARK)
    pdf.multi_cell(130, 5, grade_desc, wrapmode="WORD")

    pdf.set_y(card_y + card_h + 4)

    # ── 6 KPI mini-cards en ligne ──
    kpis = [
        ("Actifs", scan.assets_count or 0, COL_CYAN),
        ("En ligne", scan.alive_count or 0, COL_GREEN),
        ("Vulnérabilités", scan.vulns_count or 0, COL_VIOLET if scan.vulns_count else COL_TEXT_DIM),
        ("Critiques", scan.critical_count or 0, COL_RED if scan.critical_count else COL_TEXT_DIM),
        ("Élevées", scan.high_count or 0, COL_ORANGE if scan.high_count else COL_TEXT_DIM),
        ("Exploitées (KEV)", scan.kev_count or 0, COL_RED if scan.kev_count else COL_TEXT_DIM),
    ]
    kpi_y = pdf.get_y()
    kpi_w = 29  # 6 cards de 29mm + gaps
    gap = 1
    for i, (label, value, color) in enumerate(kpis):
        x = 15 + i * (kpi_w + gap)
        # Fond carte
        pdf.set_fill_color(*COL_BG_CARD)
        pdf.rect(x, kpi_y, kpi_w, 22, style="F", round_corners=True, corner_radius=2)
        # Petit trait coloré en haut
        pdf.set_fill_color(*color)
        pdf.rect(x, kpi_y, kpi_w, 1.2, style="F")
        # Valeur
        pdf.set_xy(x, kpi_y + 4)
        pdf.set_font("dv", "B", 16)
        pdf.set_text_color(*color)
        pdf.cell(kpi_w, 8, str(value), align="C")
        # Label
        pdf.set_xy(x, kpi_y + 13)
        pdf.set_font("dv", "", 7.5)
        pdf.set_text_color(*COL_TEXT_DIM)
        pdf.cell(kpi_w, 5, label.upper(), align="C")

    pdf.set_y(kpi_y + 28)

    # ── Détail du score (breakdown) si dispo ──
    if scan.risk_breakdown:
        pdf.section_title("Détail du calcul", color=COL_VIOLET)
        pdf.set_font("dv", "", 9.5)
        for item in scan.risk_breakdown[:8]:
            label = item.get("label", "")
            delta = item.get("delta", 0)
            reason = item.get("reason", "")
            line_y = pdf.get_y()
            # Pastille couleur delta
            c = COL_RED if delta < 0 else COL_GREEN
            pdf.set_fill_color(*c)
            pdf.rect(15, line_y + 1.5, 17, 5, style="F", round_corners=True, corner_radius=1)
            pdf.set_font("dv", "B", 8.5)
            pdf.set_text_color(*COL_WHITE)
            pdf.set_xy(15, line_y + 1.5)
            pdf.cell(17, 5, f"{delta:+d} pts", align="C")
            # Label en gras
            pdf.set_font("dv", "B", 10)
            pdf.set_text_color(*COL_TEXT_DARK)
            pdf.set_xy(35, line_y + 1)
            pdf.cell(160, 5, label)
            # Raison sur ligne suivante en gris
            pdf.set_xy(35, line_y + 5.5)
            pdf.set_font("dv", "", 9)
            pdf.set_text_color(*COL_TEXT_DIM)
            pdf.multi_cell(160, 4.5, reason, wrapmode="WORD")
            pdf.ln(1)

    # ════════════════════════════════════════════════════════════
    # PAGE 2 — ANALYSE EXÉCUTIVE + EMAIL/DNS
    # ════════════════════════════════════════════════════════════

    if scan.ai_summary or scan.spf or scan.dmarc or scan.dkim:
        pdf.add_page()

    # ── Analyse ARGUS ──
    if scan.ai_summary:
        pdf.section_title("Analyse ARGUS Security", color=COL_VIOLET)
        # Box gris-violet
        analyse_text = _clean_text(scan.ai_summary)
        # Estimer la hauteur
        lines = analyse_text.split("\n")
        est_height = sum(max(1, len(line) // 80 + 1) for line in lines) * 5.5 + 10
        est_height = min(est_height, 200)

        card_start = pdf.get_y()
        pdf.set_fill_color(*COL_BG_VIOLET)
        pdf.rect(15, card_start, 180, est_height, style="F",
                 round_corners=True, corner_radius=3)
        # Border-left violet
        pdf.set_fill_color(*COL_VIOLET)
        pdf.rect(15, card_start, 1.5, est_height, style="F")

        pdf.set_xy(20, card_start + 4)
        pdf.set_font("dv", "", 10.5)
        pdf.set_text_color(*COL_TEXT_DARK)
        # Split en paragraphes et write
        for paragraph in [p.strip() for p in analyse_text.split("\n\n") if p.strip()]:
            pdf.set_x(20)
            pdf.multi_cell(170, 5.5, paragraph, wrapmode="WORD")
            pdf.ln(2)

        pdf.ln(3)

    # ── Sécurité Email & DNS (3 cards SPF / DKIM / DMARC) ──
    pdf.section_title("Sécurité Email & DNS", color=COL_CYAN)
    spf = scan.spf or {}
    dmarc = scan.dmarc or {}
    dkim = scan.dkim or {}

    cards = [
        ("SPF", spf.get("present"),
         "Politique d'envoi configurée" if spf.get("present") else "Aucune politique — usurpation facile"),
        ("DKIM", dkim.get("present"),
         "Signature cryptographique active" if dkim.get("present") else "Pas de signature — emails non vérifiables"),
        ("DMARC", dmarc.get("present"),
         "Protection anti-phishing active" if dmarc.get("present") else "Pas de DMARC — phishing au nom du domaine non bloqué"),
    ]
    card_y = pdf.get_y()
    card_w = 58
    gap_h = 6
    for i, (name, ok, msg) in enumerate(cards):
        x = 15 + i * (card_w + gap_h)
        color = COL_GREEN if ok else COL_RED
        # Fond
        pdf.set_fill_color(*COL_BG_CARD)
        pdf.rect(x, card_y, card_w, 32, style="F", round_corners=True, corner_radius=2)
        # Header coloré
        pdf.set_fill_color(*color)
        pdf.rect(x, card_y, card_w, 7, style="F", round_corners=True, corner_radius=2)
        # Nom + statut
        pdf.set_font("dv", "B", 11)
        pdf.set_text_color(*COL_WHITE)
        pdf.set_xy(x, card_y + 1)
        pdf.cell(card_w / 2, 5, f"  {name}")
        pdf.set_font("dv", "", 9)
        pdf.set_xy(x + card_w / 2 - 5, card_y + 1)
        pdf.cell(card_w / 2, 5, "✓ Présent" if ok else "✗ Absent", align="R")
        # Message
        pdf.set_xy(x + 3, card_y + 11)
        pdf.set_font("dv", "", 8.5)
        pdf.set_text_color(*COL_TEXT_DARK)
        pdf.multi_cell(card_w - 6, 4.3, msg, wrapmode="WORD")

    pdf.set_y(card_y + 36)

    # ════════════════════════════════════════════════════════════
    # PAGE 3+ — VULNÉRABILITÉS
    # ════════════════════════════════════════════════════════════
    if vulns:
        # Garde en page 2 si y'a la place, sinon nouvelle page
        if pdf.get_y() > 200:
            pdf.add_page()

        pdf.section_title(f"Vulnérabilités identifiées ({len(vulns)})", color=COL_RED)
        for v in vulns[:25]:
            sev = (v.severity or "info").lower()
            sev_color = _severity_color(sev)
            name = v.name or v.template_id or "?"

            line_y = pdf.get_y()
            # Vérif page break
            if line_y > 260:
                pdf.add_page()
                line_y = pdf.get_y()

            # Badge sévérité
            pdf.set_fill_color(*sev_color)
            pdf.rect(15, line_y + 1, 22, 5, style="F", round_corners=True, corner_radius=1)
            pdf.set_font("dv", "B", 8)
            pdf.set_text_color(*COL_WHITE)
            pdf.set_xy(15, line_y + 1)
            pdf.cell(22, 5, sev.upper(), align="C")

            # Nom vuln
            pdf.set_xy(40, line_y + 0.5)
            pdf.set_font("dv", "B", 10)
            pdf.set_text_color(*COL_TEXT_DARK)
            pdf.cell(155, 5, _truncate(name, 90))

            # URL + CVE
            pdf.set_xy(40, line_y + 5.5)
            pdf.set_font("dv", "", 8.5)
            pdf.set_text_color(*COL_TEXT_DIM)
            sub = f"URL : {_truncate(v.matched_url or '—', 75)}"
            if v.cve_id:
                sub += f"  ·  {v.cve_id}"
            if v.kev:
                sub += "  ·  ⚠ KEV"
            pdf.multi_cell(155, 4.5, sub, wrapmode="CHAR")
            pdf.ln(0.5)

        if len(vulns) > 25:
            pdf.set_font("dv", "I", 9)
            pdf.set_text_color(*COL_TEXT_DIM)
            pdf.ln(2)
            pdf.cell(0, 5,
                     f"… {len(vulns) - 25} vulnérabilité(s) supplémentaire(s) non affichée(s) dans ce PDF.",
                     new_x="LMARGIN", new_y="NEXT")

    # ════════════════════════════════════════════════════════════
    # PAGE FINALE — ACTIFS IDENTIFIÉS
    # ════════════════════════════════════════════════════════════
    if assets:
        pdf.add_page()
        pdf.section_title(f"Actifs identifiés ({len(assets)})", color=COL_CYAN)

        # Header colonnes
        pdf.set_fill_color(*COL_BG_CARD)
        head_y = pdf.get_y()
        pdf.rect(15, head_y, 180, 7, style="F")
        pdf.set_font("dv", "B", 8.5)
        pdf.set_text_color(*COL_TEXT_DIM)
        pdf.set_xy(17, head_y + 1.5)
        pdf.cell(110, 4, "URL")
        pdf.set_xy(127, head_y + 1.5)
        pdf.cell(15, 4, "STATUT", align="C")
        pdf.set_xy(145, head_y + 1.5)
        pdf.cell(50, 4, "TECHNOLOGIES")
        pdf.set_y(head_y + 8)

        # Lignes
        pdf.set_font("dv", "", 8.5)
        for i, a in enumerate(assets[:80]):
            row_y = pdf.get_y()
            if row_y > 265:
                pdf.add_page()
                row_y = pdf.get_y()

            # Bandage alterné
            if i % 2 == 0:
                pdf.set_fill_color(248, 250, 252)
                pdf.rect(15, row_y, 180, 6, style="F")

            # URL (avec wrap CHAR si trop longue)
            url = a.url or ""
            status = a.status_code or 0
            tech = ", ".join((a.tech or [])[:3]) if a.tech else ""

            pdf.set_xy(17, row_y + 1.5)
            pdf.set_text_color(*COL_TEXT_DARK)
            pdf.cell(108, 3.5, _truncate(url, 60))

            # Statut coloré
            status_color = (COL_GREEN if 200 <= status < 300 else
                            COL_YELLOW if 300 <= status < 400 else
                            COL_ORANGE if 400 <= status < 500 else
                            COL_RED if status >= 500 else COL_TEXT_DIM)
            pdf.set_xy(127, row_y + 1.5)
            pdf.set_font("dv", "B", 8.5)
            pdf.set_text_color(*status_color)
            pdf.cell(15, 3.5, str(status) if status else "—", align="C")

            # Tech
            pdf.set_xy(145, row_y + 1.5)
            pdf.set_font("dv", "", 8)
            pdf.set_text_color(*COL_TEXT_DIM)
            pdf.cell(50, 3.5, _truncate(tech, 28))

            pdf.set_y(row_y + 6)

        if len(assets) > 80:
            pdf.ln(3)
            pdf.set_font("dv", "I", 9)
            pdf.set_text_color(*COL_TEXT_DIM)
            pdf.cell(0, 5,
                     f"… {len(assets) - 80} actif(s) supplémentaire(s) non affiché(s).",
                     new_x="LMARGIN", new_y="NEXT")

    # ── Note légale finale ──
    pdf.ln(10)
    pdf.set_font("dv", "I", 8.5)
    pdf.set_text_color(*COL_TEXT_DIM)
    pdf.multi_cell(180,
                   4.5,
                   "Ce rapport est confidentiel et destiné exclusivement au propriétaire du domaine scanné. "
                   "Les éléments présentés reflètent l'état de l'exposition publique du domaine au moment du scan. "
                   "Une re-évaluation régulière est recommandée pour maintenir une posture de sécurité optimale.",
                   wrapmode="WORD")

    # Output
    pdf_bytes = pdf.output(dest="S")
    if isinstance(pdf_bytes, str):
        pdf_bytes = pdf_bytes.encode("latin-1")
    elif isinstance(pdf_bytes, bytearray):
        pdf_bytes = bytes(pdf_bytes)
    return pdf_bytes
