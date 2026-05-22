"""
blog.py — Gestion des articles de blog ARGUS Security.

Articles stockés en fichiers Markdown avec frontmatter YAML dans `app/blog_content/`.
Parsing maison (zéro dépendance externe ajoutée) pour rester léger.

Frontmatter attendu (séparé par --- en haut du fichier) :
    title: "Comment scanner son site web pour les vulnérabilités"
    slug: scanner-securite-site-web
    description: "Méta-description SEO (~155 chars max)"
    keywords: scanner sécurité, audit site web, vulnérabilités web
    date: 2026-05-22
    reading_time: 8 min
    category: Audit
"""

from pathlib import Path
import re
import html as html_lib

BLOG_DIR = Path(__file__).parent / "blog_content"


def _parse_frontmatter(text: str) -> tuple[dict, str]:
    """Sépare le frontmatter YAML (entre ---) du body markdown."""
    if not text.startswith("---"):
        return {}, text
    parts = text.split("---", 2)
    if len(parts) < 3:
        return {}, text
    fm_raw = parts[1].strip()
    body = parts[2].strip()
    fm = {}
    for line in fm_raw.split("\n"):
        line = line.strip()
        if not line or ":" not in line:
            continue
        k, _, v = line.partition(":")
        fm[k.strip()] = v.strip().strip('"').strip("'")
    return fm, body


def _md_to_html(md: str) -> str:
    """
    Parser markdown maison léger. Supporte :
    - # / ## / ### titres
    - ** bold ** / * italic *
    - [link](url)
    - listes - et 1.
    - > blockquotes
    - ``` code blocks ```
    - ` inline code `
    - --- séparateurs
    - paragraphes auto
    """
    lines = md.split("\n")
    out = []
    i = 0
    in_code_block = False
    code_lang = ""
    code_buffer = []

    def _inline(t: str) -> str:
        """Inline formatting : escape HTML puis injecte les balises md."""
        # Échapper HTML d'abord (sauf si dans une balise on a déjà mis)
        t = html_lib.escape(t)
        # `inline code` → <code> (avant les liens pour pas bouffer les ` dans urls)
        t = re.sub(r"`([^`\n]+)`", r"<code>\1</code>", t)
        # [text](url) → <a>
        t = re.sub(
            r"\[([^\]]+)\]\(([^)]+)\)",
            lambda m: f'<a href="{m.group(2)}" target="_blank" rel="noopener">{m.group(1)}</a>',
            t,
        )
        # **bold**
        t = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", t)
        # *italic*
        t = re.sub(r"(?<!\*)\*([^*\n]+)\*(?!\*)", r"<em>\1</em>", t)
        return t

    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        # Code blocks ```
        if stripped.startswith("```"):
            if in_code_block:
                out.append(f'<pre><code class="lang-{code_lang}">' + html_lib.escape("\n".join(code_buffer)) + "</code></pre>")
                code_buffer = []
                in_code_block = False
                code_lang = ""
            else:
                in_code_block = True
                code_lang = stripped[3:].strip() or "text"
            i += 1
            continue
        if in_code_block:
            code_buffer.append(line)
            i += 1
            continue

        # Titres
        m = re.match(r"^(#{1,6})\s+(.+)$", stripped)
        if m:
            level = len(m.group(1))
            text = _inline(m.group(2))
            # On commence à h2 (le h1 c'est le titre de l'article)
            real_level = max(2, level)
            slug = re.sub(r"[^a-z0-9-]", "", m.group(2).lower().replace(" ", "-"))[:60]
            out.append(f'<h{real_level} id="{slug}">{text}</h{real_level}>')
            i += 1
            continue

        # Séparateur ---
        if re.match(r"^-{3,}$", stripped):
            out.append("<hr>")
            i += 1
            continue

        # Blockquote >
        if stripped.startswith(">"):
            quote_lines = []
            while i < len(lines) and lines[i].strip().startswith(">"):
                quote_lines.append(lines[i].strip().lstrip(">").strip())
                i += 1
            out.append("<blockquote><p>" + _inline(" ".join(quote_lines)) + "</p></blockquote>")
            continue

        # Liste non ordonnée
        if re.match(r"^[-*]\s+", stripped):
            items = []
            while i < len(lines) and re.match(r"^[-*]\s+", lines[i].strip()):
                items.append(_inline(re.sub(r"^[-*]\s+", "", lines[i].strip())))
                i += 1
            out.append("<ul>" + "".join(f"<li>{it}</li>" for it in items) + "</ul>")
            continue

        # Liste ordonnée
        if re.match(r"^\d+\.\s+", stripped):
            items = []
            while i < len(lines) and re.match(r"^\d+\.\s+", lines[i].strip()):
                items.append(_inline(re.sub(r"^\d+\.\s+", "", lines[i].strip())))
                i += 1
            out.append("<ol>" + "".join(f"<li>{it}</li>" for it in items) + "</ol>")
            continue

        # Paragraphe : agglutine lignes consécutives non vides
        if stripped:
            para_lines = []
            while i < len(lines) and lines[i].strip() and not _is_block_start(lines[i].strip()):
                para_lines.append(lines[i].strip())
                i += 1
            out.append("<p>" + _inline(" ".join(para_lines)) + "</p>")
            continue

        # Ligne vide
        i += 1

    return "\n".join(out)


def _is_block_start(stripped: str) -> bool:
    """Détecte si une ligne démarre un bloc spécial (titre, liste, etc.)"""
    return (
        stripped.startswith("#")
        or stripped.startswith(">")
        or stripped.startswith("```")
        or re.match(r"^[-*]\s+", stripped) is not None
        or re.match(r"^\d+\.\s+", stripped) is not None
        or re.match(r"^-{3,}$", stripped) is not None
    )


def _load_article_file(path: Path) -> dict:
    """Charge un fichier .md → dict avec frontmatter + HTML body."""
    text = path.read_text(encoding="utf-8")
    fm, body_md = _parse_frontmatter(text)
    body_html = _md_to_html(body_md)
    return {
        "slug": fm.get("slug", path.stem),
        "title": fm.get("title", path.stem),
        "description": fm.get("description", ""),
        "keywords": fm.get("keywords", ""),
        "date": fm.get("date", ""),
        "reading_time": fm.get("reading_time", ""),
        "category": fm.get("category", ""),
        "body_html": body_html,
    }


def get_all_articles() -> list[dict]:
    """Retourne tous les articles, triés par date desc."""
    if not BLOG_DIR.exists():
        return []
    articles = []
    for path in BLOG_DIR.glob("*.md"):
        try:
            articles.append(_load_article_file(path))
        except Exception as e:
            print(f"[BLOG ERROR] {path.name}: {e}", flush=True)
    articles.sort(key=lambda a: a.get("date", ""), reverse=True)
    return articles


def get_article(slug: str) -> dict | None:
    """Récupère un article par son slug."""
    for art in get_all_articles():
        if art["slug"] == slug:
            return art
    return None
