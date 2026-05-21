"""
pupelmet.py — Mini-Pupelmet Sprint 0
=====================================

Ce script fait en 30 secondes ce que Benjamin Krown faisait à la main :
   1. Découvrir tous les sous-domaines d'un domaine cible
   2. Tester chacun pour voir lesquels sont vivants (= répondent en HTTP)
   3. Détecter quelle techno tourne derrière (WordPress, nginx, etc.)
   4. Sauvegarder les résultats en JSON (= fichier exploitable)
   5. Demander à Claude IA un résumé en français pour le CISO

USAGE :
    python pupelmet.py <domaine>

EXEMPLES :
    python pupelmet.py compucom.ma
    python pupelmet.py uae.ma          # le 871-webapps de l'email avril 2025
    python pupelmet.py um6p.ma         # le 174-webapps de l'email février 2024
    python pupelmet.py purplemet.com   # savoure l'ironie
"""

# ─────────────────────────────────────────────────────────────────────
# IMPORTS — on importe les outils dont on a besoin
# (En Python, "import" = "va chercher ce module et rends-le dispo ici")
# ─────────────────────────────────────────────────────────────────────

# Modules de la "bibliothèque standard" (= livrés avec Python, pas besoin d'installer)
import json          # Pour lire/écrire des fichiers JSON
import os            # Pour interagir avec le système (variables d'env, chemins...)
import subprocess    # Pour lancer des programmes externes (= subfinder, httpx)
import sys           # Pour récupérer les arguments passés en ligne de commande
from datetime import datetime  # Pour timestamper les fichiers de sortie
from pathlib import Path       # Pour manipuler des chemins de fichiers proprement

# Modules externes (= installés via "uv sync" ou "pip install")
# Ces libs sont déclarées dans pyproject.toml
from dotenv import load_dotenv               # Lit les variables du fichier .env
from rich.console import Console             # Affichage terminal moderne (couleurs)
from rich.table import Table                 # Tableaux dans le terminal
from rich.panel import Panel                 # Boîtes encadrées pour le résumé IA
from rich.progress import Progress, SpinnerColumn, TextColumn  # Barres de chargement
from anthropic import Anthropic              # SDK officiel pour parler à Claude


# ─────────────────────────────────────────────────────────────────────
# CONFIG — quelques constantes à un seul endroit
# ─────────────────────────────────────────────────────────────────────

# Chemins (Path = objet "chemin de fichier" intelligent qui marche sur Windows ET Mac/Linux)
ROOT = Path(__file__).parent  # Le dossier du projet (où ce fichier .py est rangé)
TOOLS_DIR = ROOT / "tools" / "bin"
SCANS_DIR = ROOT / "scans"
SUBFINDER = TOOLS_DIR / "subfinder.exe"
HTTPX = TOOLS_DIR / "httpx.exe"

# Modèle IA à utiliser pour le résumé
# (Claude Sonnet 4.6 = bon équilibre rapidité/qualité pour ce genre de synthèse)
CLAUDE_MODEL = "claude-sonnet-4-6"

# Objet Console = ce qui affiche dans le terminal (avec couleurs, etc.)
console = Console()


# ─────────────────────────────────────────────────────────────────────
# FONCTION 1 — Découverte des sous-domaines (subfinder)
# ─────────────────────────────────────────────────────────────────────

def run_subfinder(domain: str) -> list[str]:
    """
    Lance subfinder pour trouver tous les sous-domaines d'un domaine.

    EXEMPLE concret :
        run_subfinder("compucom.ma") → ["mail.compucom.ma", "vpn.compucom.ma", ...]

    (subfinder cherche dans 30+ sources OSINT — Certificate Transparency,
     archives DNS, Shodan, etc. — SANS frapper le site cible directement.
     C'est ce qu'on appelle une découverte "passive" : aucun trafic envoyé
     au domaine victime, donc invisible, donc 100% légal.)
    """
    # subprocess.run() = lance une commande externe (comme si on l'avait tapée dans le terminal)
    # On lance : `subfinder.exe -d <domaine> -silent`
    #   -d <domaine> = le domaine cible
    #   -silent      = pas de banner ni de logs, juste les résultats
    result = subprocess.run(
        [str(SUBFINDER), "-d", domain, "-silent"],
        capture_output=True,  # On capture stdout/stderr pour les lire en Python
        text=True,            # On veut du texte (pas des bytes bruts)
        timeout=120,          # On limite à 2 minutes max (sécurité)
    )

    # stdout = ce que subfinder a affiché (un sous-domaine par ligne)
    # .splitlines() = on coupe sur les retours à la ligne → liste de strings
    # set() = on dédoublonne au cas où subfinder répèterait
    # filter(None, ...) = on enlève les lignes vides
    subdomains = sorted(set(filter(None, result.stdout.splitlines())))

    # On retourne aussi le domaine racine (= le domaine lui-même)
    # pour qu'il soit testé en HTTP comme les autres
    if domain not in subdomains:
        subdomains.insert(0, domain)

    return subdomains


# ─────────────────────────────────────────────────────────────────────
# FONCTION 2 — Probing HTTP + détection techno (httpx)
# ─────────────────────────────────────────────────────────────────────

def run_httpx(subdomains: list[str]) -> list[dict]:
    """
    Pour chaque sous-domaine, vérifie s'il répond en HTTP et identifie la techno.

    EXEMPLE concret :
        Input  : ["mail.compucom.ma", "old.compucom.ma"]
        Output : [
            {"url": "https://mail.compucom.ma", "status_code": 200,
             "tech": ["Microsoft Exchange"], "title": "Outlook Web Access"},
            {"url": "https://old.compucom.ma", "status_code": 0, ...}  (pas de réponse)
        ]

    (httpx = un "probe" HTTP qui frappe à la porte et écoute la réponse.
     Il détecte aussi les technos via les headers HTTP et le HTML.
     Ex: si la réponse contient "X-Powered-By: PHP/7.4" → il sait que c'est PHP 7.4.)
    """
    if not subdomains:
        return []

    # On donne la liste à httpx via stdin (= "entrée standard")
    # C'est le truc Unix classique : `echo "domaine.com" | httpx`
    input_text = "\n".join(subdomains)

    result = subprocess.run(
        [
            str(HTTPX),
            "-json",          # Sortie au format JSON (1 ligne JSON par sous-domaine)
            "-silent",        # Pas de logs
            "-title",         # Récupère le <title> de la page
            "-tech-detect",   # Active la détection techno
            "-status-code",   # Récupère le code HTTP (200, 404, etc.)
            "-no-color",      # Pas de codes couleur ANSI dans la sortie
            "-timeout", "10", # 10 secondes max par sous-domaine
        ],
        input=input_text,
        capture_output=True,
        text=True,
        timeout=300,  # 5 minutes max au total
    )

    # On parse chaque ligne JSON que httpx a sortie
    findings = []
    for line in result.stdout.splitlines():
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
            findings.append({
                "url": entry.get("url", ""),
                "host": entry.get("host", ""),
                "status_code": entry.get("status_code", 0),
                "title": entry.get("title", ""),
                "tech": entry.get("tech", []),
                "webserver": entry.get("webserver", ""),
                "content_length": entry.get("content_length", 0),
            })
        except json.JSONDecodeError:
            # Si une ligne n'est pas du JSON valide, on saute (= robustesse)
            continue

    return findings


# ─────────────────────────────────────────────────────────────────────
# FONCTION 3 — Résumé IA (Claude Sonnet 4.6)
# ─────────────────────────────────────────────────────────────────────

def ai_summarize(domain: str, findings: list[dict]) -> str:
    """
    Envoie les findings à Claude qui rédige un résumé exécutif en français.

    EXEMPLE de sortie :
        "Sur compucom.ma, j'ai identifié 12 actifs web exposés.
        3 utilisent des technos en fin de vie (Apache 2.2). Un panneau
        d'admin Joomla est accessible publiquement... [etc]"

    (C'est exactement ce que tu demandais à Benjamin Krown :
     traduire les findings techniques en quelque chose qu'un dirigeant comprend.)
    """
    # Récupère la clé API depuis .env (chargée plus tôt avec load_dotenv())
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key or api_key.startswith("sk-ant-..."):
        return "[Résumé IA désactivé : ANTHROPIC_API_KEY manquante dans .env]"

    # Le "prompt" = la question/instruction qu'on envoie à l'IA.
    # On lui donne :
    #   1. Un rôle (= "tu es un consultant cybersécurité")
    #   2. Du contexte (= le domaine + les findings)
    #   3. Une consigne claire (= format de sortie attendu)
    findings_text = json.dumps(findings, indent=2, ensure_ascii=False)
    prompt = f"""Tu es un consultant cybersécurité francophone qui prépare un brief de 3 paragraphes maximum pour un CISO non-technique.

Tu viens de scanner le domaine : {domain}

Voici les actifs web découverts (format JSON) :
{findings_text}

Rédige un résumé en français de 3 paragraphes courts, accessible à un dirigeant non-tech :
- Paragraphe 1 : Ce que j'ai trouvé (volume, surface d'attaque)
- Paragraphe 2 : Les 2-3 risques les plus inquiétants (avec exemples concrets)
- Paragraphe 3 : Action recommandée (1 phrase, claire et actionnable)

Pas de jargon technique sans le traduire. Pas de listes à puces. Du texte naturel."""

    # On instancie le client Anthropic (= notre porte d'entrée vers l'API Claude)
    client = Anthropic(api_key=api_key)

    # On envoie la requête à Claude
    # (max_tokens = limite de longueur de la réponse, en "tokens" ≈ mots)
    response = client.messages.create(
        model=CLAUDE_MODEL,
        max_tokens=800,
        messages=[{"role": "user", "content": prompt}],
    )

    # La réponse arrive en plusieurs "blocks" (généralement 1 seul block de texte)
    return response.content[0].text


# ─────────────────────────────────────────────────────────────────────
# FONCTION 4 — Affichage des résultats (tableau + résumé)
# ─────────────────────────────────────────────────────────────────────

def display_results(domain: str, findings: list[dict], summary: str) -> None:
    """Affiche un beau tableau dans le terminal + le résumé IA."""

    # En-tête
    console.print()
    console.print(Panel.fit(
        f"[bold magenta]PUPELMET — scan de [cyan]{domain}[/]",
        border_style="magenta",
    ))

    # Compteur de findings
    alive = [f for f in findings if f.get("status_code", 0) > 0]
    console.print(f"\n[bold]{len(findings)}[/] actifs découverts — "
                  f"[green]{len(alive)}[/] vivants (répondent en HTTP)\n")

    # Tableau Rich (= équivalent d'un Excel formaté dans le terminal)
    table = Table(show_lines=False, header_style="bold cyan")
    table.add_column("URL", style="white", no_wrap=False)
    table.add_column("Status", justify="center")
    table.add_column("Techno", style="yellow")
    table.add_column("Titre de page", style="dim")

    # On colore le status code selon sa valeur
    def color_status(code: int) -> str:
        if code == 0:
            return "[red]✗[/]"
        elif 200 <= code < 300:
            return f"[green]{code}[/]"
        elif 300 <= code < 400:
            return f"[blue]{code}[/]"
        elif 400 <= code < 500:
            return f"[yellow]{code}[/]"
        else:
            return f"[red]{code}[/]"

    for f in findings:
        techs = ", ".join(f.get("tech", []) or []) or "—"
        title = (f.get("title") or "")[:60]  # On tronque les longs titres
        table.add_row(
            f.get("url") or f.get("host", ""),
            color_status(f.get("status_code", 0)),
            techs,
            title,
        )

    console.print(table)

    # Résumé IA dans un panneau encadré
    console.print()
    console.print(Panel(summary, title="🤖 Résumé exécutif (Claude IA)",
                        border_style="cyan", padding=(1, 2)))
    console.print()


# ─────────────────────────────────────────────────────────────────────
# FONCTION 5 — Sauvegarde JSON
# ─────────────────────────────────────────────────────────────────────

def save_json(domain: str, findings: list[dict], summary: str) -> Path:
    """
    Sauvegarde le scan complet dans scans/<domain>_<timestamp>.json
    pour pouvoir le rejouer / l'envoyer à un client / le comparer plus tard.
    """
    SCANS_DIR.mkdir(exist_ok=True)
    # Timestamp lisible : 2026-05-18_14-30-22
    ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"{domain}_{ts}.json"
    path = SCANS_DIR / filename

    payload = {
        "domain": domain,
        "scanned_at": datetime.now().isoformat(),
        "findings_count": len(findings),
        "alive_count": sum(1 for f in findings if f.get("status_code", 0) > 0),
        "findings": findings,
        "ai_summary": summary,
    }

    # ensure_ascii=False = on garde les accents/emojis tels quels dans le JSON
    path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    return path


# ─────────────────────────────────────────────────────────────────────
# MAIN — l'orchestrateur (= le chef d'orchestre qui appelle tout dans l'ordre)
# ─────────────────────────────────────────────────────────────────────

def main() -> None:
    # On charge les variables du fichier .env dans os.environ
    # (= rend la clé API accessible via os.getenv("ANTHROPIC_API_KEY"))
    load_dotenv()

    # Lecture de l'argument passé sur la ligne de commande
    # sys.argv = ["pupelmet.py", "compucom.ma"] si on lance `python pupelmet.py compucom.ma`
    if len(sys.argv) < 2:
        console.print("[red]Usage :[/] python pupelmet.py <domaine>")
        console.print("[dim]Exemple : python pupelmet.py compucom.ma[/]")
        sys.exit(1)

    domain = sys.argv[1].strip().lower()

    # Vérifications préalables (= les binaires sont bien là)
    if not SUBFINDER.exists():
        console.print(f"[red]subfinder.exe introuvable[/] dans {TOOLS_DIR}")
        console.print("[yellow]Lance d'abord : .\\tools\\install_tools.ps1[/]")
        sys.exit(1)
    if not HTTPX.exists():
        console.print(f"[red]httpx.exe introuvable[/] dans {TOOLS_DIR}")
        console.print("[yellow]Lance d'abord : .\\tools\\install_tools.ps1[/]")
        sys.exit(1)

    # Spinner = la petite roue qui tourne dans le terminal pendant qu'on attend
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,  # Le spinner disparaît une fois fini
    ) as progress:

        # Étape 1 : découverte
        task = progress.add_task(f"[cyan]Découverte des sous-domaines de {domain}...", total=None)
        subdomains = run_subfinder(domain)
        progress.update(task, description=f"[green]✓ {len(subdomains)} sous-domaines trouvés")
        progress.stop_task(task)

        # Étape 2 : probing HTTP
        task = progress.add_task(f"[cyan]Test HTTP + détection techno...", total=None)
        findings = run_httpx(subdomains)
        progress.update(task, description=f"[green]✓ {len(findings)} actifs testés")
        progress.stop_task(task)

        # Étape 3 : résumé IA
        task = progress.add_task("[cyan]Génération du résumé IA (Claude)...", total=None)
        summary = ai_summarize(domain, findings)
        progress.update(task, description="[green]✓ Résumé IA généré")
        progress.stop_task(task)

    # Affichage final
    display_results(domain, findings, summary)

    # Sauvegarde
    path = save_json(domain, findings, summary)
    console.print(f"[dim]💾 Résultats sauvegardés → {path}[/]\n")


# Quand on lance ce fichier avec `python pupelmet.py`, Python met __name__ à "__main__"
# et exécute donc main().
# (Si on importait ce fichier depuis un autre script, __name__ serait "pupelmet" et
#  main() ne s'exécuterait pas tout seul — on l'appellerait nous-mêmes.)
if __name__ == "__main__":
    main()
