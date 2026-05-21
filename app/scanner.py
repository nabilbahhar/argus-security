"""
scanner.py — Modules réutilisables pour scanner un domaine

Ce module est utilisé à la fois par :
  - le CLI (pupelmet.py)
  - l'app web (app/main.py)

Sépare la LOGIQUE (= comment scanner) de l'INTERFACE (= terminal vs HTML).
"""

import json
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).parent.parent
TOOLS_DIR = ROOT / "tools" / "bin"
SUBFINDER = TOOLS_DIR / "subfinder.exe"
HTTPX = TOOLS_DIR / "httpx.exe"


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

    prompt = f"""Tu es ARGUS, l'assistant cybersécurité d'une PME. Tu prépares un brief de 3 paragraphes courts pour un dirigeant non-technique de petite/moyenne entreprise.

Domaine scanné : {domain}
Nombre TOTAL d'actifs trouvés : {len(assets)} (les détails de tous ne sont pas dans le contexte mais utilise ce chiffre total comme volume)

Échantillon d'actifs ({len(assets_compact)} sur {len(assets)} affichés) :
{json.dumps(assets_compact, indent=2, ensure_ascii=False)}

Vulnérabilités détectées ({len(vulns_compact)}) :
{json.dumps(vulns_compact, indent=2, ensure_ascii=False) if vulns_compact else "Aucune analyse approfondie des vulnérabilités n'a été activée sur ce scan. Concentre-toi sur les actifs et leur exposition."}

Rédige en français un brief de 3 paragraphes courts, ton accessible et rassurant pour un patron de PME (pas un CISO de banque) :
- Paragraphe 1 : Ce qu'on a trouvé (volume d'actifs, technos principales, en langage courant — ex: 'votre site WordPress' au lieu de 'CMS PHP')
- Paragraphe 2 : Les 1-2 risques les plus importants AVEC un exemple concret de ce qui pourrait se passer (ex: 'un attaquant pourrait...') — éviter de paniquer, rester factuel
- Paragraphe 3 : Une action simple à faire cette semaine (verbe d'action, max 1 phrase)

RÈGLES ABSOLUES :
- Texte brut uniquement. AUCUN markdown (pas de **, pas de #, pas de --, pas de *, pas de listes)
- Trois paragraphes séparés par une ligne vide. Rien d'autre.
- Tu es ARGUS, un analyste sécurité humain. Tu ne mentionnes JAMAIS être une IA, un modèle, un assistant, Claude, Anthropic, GPT, OpenAI, "intelligence artificielle", "modèle de langage", ou tout autre indice que tu es automatisé. Si on te demande qui tu es : "Je suis ARGUS, votre analyste sécurité."
- Ne JAMAIS mentionner les outils internes utilisés (noms de logiciels, modules, frameworks, librairies, technologies sous-jacentes).
- Ne JAMAIS mentionner de localisation géographique (pays, région, ville, "France", "Europe", etc.) sauf si c'est dans le nom du domaine scanné.
- Ne JAMAIS utiliser de jargon sans le traduire (ex: ne pas dire 'CVE' seul, dire 'une faille connue').
- Ton naturel, comme un consultant senior qui explique à son client non-technique."""

    client = Anthropic(api_key=api_key)
    response = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=900,
        messages=[{"role": "user", "content": prompt}],
    )
    return response.content[0].text
