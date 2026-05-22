"""
scanner.py — Modules réutilisables pour scanner un domaine.

Sépare la logique (comment scanner) de l'interface (FastAPI routes).
"""

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
TOOLS_DIR = ROOT / "tools" / "bin"
_EXE = ".exe" if sys.platform == "win32" else ""
SUBFINDER = TOOLS_DIR / f"subfinder{_EXE}"
HTTPX = TOOLS_DIR / f"httpx{_EXE}"


def run_subfinder(domain: str, timeout: int = 600) -> list[str]:
    """
    Découvre les sous-domaines d'un domaine via subfinder (passive OSINT).

    Retourne une liste triée + dédoublonnée + incluant le domaine racine.

    Args:
        timeout: 600 sec (10 min) par défaut — suffisant pour gros domaines (uae.ma, etc.)
    """
    if not SUBFINDER.exists():
        raise FileNotFoundError(f"subfinder.exe manquant : {SUBFINDER}")

    result = subprocess.run(
        [
            str(SUBFINDER),
            "-d", domain,
            "-silent",
            "-timeout", "30",  # timeout par source (en sec)
            "-t", "50",        # 50 threads en parallèle pour aller vite
        ],
        capture_output=True,
        text=True,
        timeout=timeout,
        encoding="utf-8",
        errors="replace",
    )

    subs = sorted(set(filter(None, result.stdout.splitlines())))
    if domain not in subs:
        subs.insert(0, domain)
    return subs


def run_httpx(subdomains: list[str], timeout: int = 900) -> list[dict]:
    """
    Probe chaque sous-domaine + détecte techno + récupère metadata HTTP.
    """
    if not HTTPX.exists():
        raise FileNotFoundError(f"httpx.exe manquant : {HTTPX}")
    if not subdomains:
        return []

    input_text = "\n".join(subdomains)
    result = subprocess.run(
        [
            str(HTTPX),
            "-json",
            "-silent",
            "-title",
            "-tech-detect",
            "-status-code",
            "-no-color",
            "-timeout", "10",     # timeout par requête
            "-threads", "100",    # 100 requêtes en parallèle (au lieu de 50 par défaut)
            "-retries", "1",      # 1 seul retry au lieu de 3 (plus rapide)
        ],
        input=input_text,
        capture_output=True,
        text=True,
        timeout=timeout,
        encoding="utf-8",
        errors="replace",
    )

    findings = []
    for line in result.stdout.splitlines():
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
            findings.append({
                "url": entry.get("url", ""),
                "host": entry.get("host", ""),
                "status_code": int(entry.get("status_code", 0) or 0),
                "title": entry.get("title", "") or "",
                "tech": entry.get("tech", []) or [],
                "webserver": entry.get("webserver", "") or "",
                "content_length": int(entry.get("content_length", 0) or 0),
            })
        except (json.JSONDecodeError, ValueError):
            continue

    return findings


def ai_summarize(domain: str, assets: list[dict], vulns: list[dict] | None = None) -> str:
    """
    Demande à Claude un brief exécutif en français à partir des findings.
    """
    from anthropic import Anthropic

    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key or api_key.startswith("sk-ant-..."):
        return "[Résumé IA désactivé : ANTHROPIC_API_KEY manquante]"

    # Limite la taille des findings envoyés pour rester sous quota
    assets_compact = [
        {
            "url": a.get("url"),
            "status": a.get("status_code"),
            "tech": a.get("tech", []),
            "title": (a.get("title") or "")[:200],
        }
        for a in assets[:50]
    ]

    vulns_compact = []
    for v in (vulns or [])[:30]:
        vulns_compact.append({
            "name": v.get("name"),
            "severity": v.get("severity"),
            "url": v.get("matched_url"),
            "cve": v.get("cve_id"),
        })

    prompt = f"""Tu es ARGUS, analyste sécurité senior chargé d'un audit externe de reconnaissance.
Ton job : alerter le propriétaire du domaine sur tout ce qu'un attaquant verrait s'il le ciblait.
On ne banalise JAMAIS. Chaque actif exposé publiquement est une porte d'entrée potentielle.
Mais on n'invente rien : on s'appuie uniquement sur les findings réels du scan.

Domaine audité : {domain}
Actifs trouvés en tout : {len(assets)}
Échantillon ({len(assets_compact)} sur {len(assets)}) :
{json.dumps(assets_compact, indent=2, ensure_ascii=False)}

Vulnérabilités détectées ({len(vulns_compact)}) :
{json.dumps(vulns_compact, indent=2, ensure_ascii=False) if vulns_compact else "Aucune analyse approfondie de vulnérabilités sur ce scan — concentre-toi sur l'exposition et les patterns d'actifs."}

Rédige un brief de 3 paragraphes courts, ton direct et lucide (pas alarmiste mais jamais "tout va bien") :

PARAGRAPHE 1 — Ce qu'un attaquant voit déjà de ce domaine.
Volume d'actifs + technos principales identifiables (WordPress, PHP X.Y, nginx, etc. — cite les versions précises si fournies). Mentionne explicitement les sous-domaines au nom suspect s'il y en a (bo.*, admin.*, old.*, dev.*, staging.*, test.*) — ce sont les premières cibles. Si tu vois des versions précises (PHP 8.1, jQuery 1.x, WordPress 5.x), dis qu'elles permettent à un attaquant de cibler les CVE connues de cette version exacte.

PARAGRAPHE 2 — Les 2-3 risques les plus exploitables ICI, avec scénarios concrets.
Pour chaque risque : "Un attaquant pourrait…" puis l'enchaînement réaliste (énumération, brute-force, exploitation CVE, pivot). Donne au moins UN risque même si le scan est "propre" — il y a TOUJOURS un angle (technos identifiées dans les headers, sous-domaines non sécurisés par défaut, absence DMARC = phishing facile, etc.). Ne dis JAMAIS "votre sécurité est exemplaire" ou "tout est en ordre" : il y a toujours quelque chose à durcir.

PARAGRAPHE 3 — Ce qu'il faut faire dans les 7 prochains jours.
2 ou 3 actions concrètes, verbes d'action, priorisées. Pas "vous devriez envisager", mais "isolez X derrière un VPN", "supprimez Y", "mettez à jour Z". Si findings critiques : "URGENT, à faire aujourd'hui".

RÈGLES ABSOLUES :
- Texte brut uniquement. AUCUN markdown (pas de **, pas de #, pas de listes à puces).
- Trois paragraphes séparés par une ligne vide. Rien d'autre.
- Tu es ARGUS, un analyste sécurité humain. JAMAIS mentionner IA, modèle, assistant, Claude, Anthropic, GPT, OpenAI, "intelligence artificielle", "modèle de langage", ou tout indice d'automatisation. Si on te demande qui tu es : "Je suis ARGUS, votre analyste sécurité."
- JAMAIS mentionner les outils internes utilisés (noms de scanners, frameworks, librairies techniques de notre stack).
- JAMAIS de localisation géographique (France, Europe, Maroc, francophone, etc.) sauf si dans le nom du domaine.
- JAMAIS mentionner la langue utilisée.
- Jargon traduit : "CVE" → "faille connue", "EPSS" → "probabilité d'exploitation", "KEV" → "exploit déjà utilisé en pratique".
- Ton : consultant senior expérimenté qui parle franchement à son client. Pas commercial, pas anxiogène pour rien, mais ferme sur ce qui doit être corrigé."""

    client = Anthropic(api_key=api_key)
    response = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=900,
        messages=[{"role": "user", "content": prompt}],
    )
    return response.content[0].text
