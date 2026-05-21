"""
outbound.py — Générateur d'emails de prospection IA

C'EST L'USP UNIQUE DE PUPELMET.

À partir d'un scan, on génère :
  - Un email de prospection (subject + body 3 paragraphes)
  - Un message LinkedIn court
  - 5 Q/R aux objections fréquentes

But : transformer un revendeur novice en commercial efficace dès le jour 1.
Ex : Nabil chez Compucom envoyait des emails à Benjamin pour qu'il lui prépare
le pitch. Avec ARGUS, il génère le pitch lui-même en 5 secondes.
"""

import json
import os
from anthropic import Anthropic


def generate_outbound(
    domain: str,
    assets: list[dict],
    vulns: list[dict],
    style: str = "court",
) -> dict:
    """
    Génère un pack outbound complet à partir d'un scan.

    Returns:
        {
            "subject": "...",
            "body": "...",
            "linkedin_message": "...",
            "objections": [{"q": "...", "a": "..."}, ...]
        }
    """
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key or api_key.startswith("sk-ant-..."):
        return {
            "subject": "[IA désactivée]",
            "body": "ANTHROPIC_API_KEY manquante dans .env",
            "linkedin_message": "",
            "objections": [],
        }

    # On résume les données pour rester sous quota
    assets_summary = {
        "total": len(assets),
        "alive": sum(1 for a in assets if a.get("status_code", 0) > 0),
        "top_techs": _top_techs(assets, n=8),
        "interesting_urls": [
            a.get("url") for a in assets[:15]
            if a.get("status_code", 0) > 0
        ],
    }

    vulns_summary = {
        "total": len(vulns),
        "critical": [v["name"] for v in vulns if v.get("severity") == "critical"][:5],
        "high": [v["name"] for v in vulns if v.get("severity") == "high"][:5],
        "medium_count": sum(1 for v in vulns if v.get("severity") == "medium"),
    }

    style_instructions = {
        "court": "Email de MAXIMUM 3 paragraphes très courts (4-5 lignes chacun max). Direct, pas de blabla.",
        "long": "Email plus détaillé (5-6 paragraphes) avec contexte business + chiffres.",
        "formel": "Ton très professionnel, vouvoiement strict, signature corporate.",
        "direct": "Ton direct/disruptif, comme un fondateur tech qui pitch un C-level.",
    }.get(style, "Email court et percutant.")

    prompt = f"""Tu es un expert en outbound B2B cybersécurité. Tu génères un pack commercial pour un revendeur d'ARGUS (solution de surveillance de sécurité web pour PME) qui prospecte le domaine ci-dessous.

Cible : un dirigeant ou DSI de PME (5-500 salariés), pas un CISO grand compte. Le ton doit être accessible, rassurant, pédagogique — sans jargon technique. Mettre en avant : prix abordable, confidentialité des données, simplicité.

Domaine cible : {domain}
Résultats du scan :
- Actifs web : {json.dumps(assets_summary, ensure_ascii=False)}
- Vulnérabilités : {json.dumps(vulns_summary, ensure_ascii=False)}

Style demandé : {style_instructions}

Génère un JSON STRICT (sans backticks, sans ```json, juste le JSON brut) avec ces champs :

{{
  "subject": "objet de l'email — court, intrigant, mentionne le domaine — max 70 caractères — éviter mot 'sécurité' en 1er mot (anti-spam)",
  "body": "corps de l'email en français — paragraphes séparés par double saut de ligne — pas de 'Cher M. X', commence par 'Bonjour,' — termine par 'Cordialement,\\nL'équipe ARGUS' — utilise UNIQUEMENT les chiffres donnés ci-dessus, n'en invente jamais",
  "linkedin_message": "message LinkedIn de prospection — max 250 caractères — ton direct, naturel",
  "objections": [
    {{"q": "On est trop petit pour être ciblé", "a": "réponse rassurante avec un exemple concret de PME attaquée"}},
    {{"q": "C'est trop cher pour nous", "a": "réponse mentionnant pricing à partir de 29€/mois et ROI"}},
    {{"q": "On a déjà un antivirus / pare-feu", "a": "réponse expliquant pourquoi c'est complémentaire"}},
    {{"q": "Envoyez-moi une plaquette", "a": "réponse qui propose plutôt un scan gratuit immédiat"}},
    {{"q": "On n'a pas d'expert sécurité", "a": "réponse rassurant : l'outil parle français clair, pas besoin d'expert"}}
  ]
}}

CRUCIAL :
- N'invente JAMAIS de chiffres non présents dans les données
- Ne mentionne PAS ARGUS dans l'objet (anti-spam)
- L'email doit créer une conversation, pas closer en 1 email
- Mots interdits : "leverage", "synergy", "disrupt", "innovant"
- Mentionner le prix accessible si pertinent (à partir de 29€/mois)
"""

    client = Anthropic(api_key=api_key)
    response = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=2000,
        messages=[{"role": "user", "content": prompt}],
    )
    raw = response.content[0].text.strip()

    # Nettoyage si Claude a quand même mis des backticks
    if raw.startswith("```"):
        raw = raw.strip("`").lstrip("json").strip()

    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        # Fallback : on retourne le texte brut dans body
        return {
            "subject": f"À propos de {domain}",
            "body": raw,
            "linkedin_message": "",
            "objections": [],
        }

    # On garantit que les clés sont présentes
    return {
        "subject": data.get("subject", f"À propos de {domain}"),
        "body": data.get("body", ""),
        "linkedin_message": data.get("linkedin_message", ""),
        "objections": data.get("objections", []),
    }


def _top_techs(assets: list[dict], n: int = 8) -> list[str]:
    """Retourne les n technos les plus présentes dans le parc."""
    counts: dict[str, int] = {}
    for a in assets:
        for t in a.get("tech", []) or []:
            # Normalise : on coupe la version "WordPress:6.9" -> "WordPress"
            base = t.split(":")[0].strip()
            if base:
                counts[base] = counts.get(base, 0) + 1
    return [t for t, _ in sorted(counts.items(), key=lambda kv: -kv[1])[:n]]
