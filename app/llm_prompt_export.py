"""
llm_prompt_export.py — Génère un prompt LLM téléchargeable à partir d'un scan.

Au lieu de générer un PDF (coûteux, rigide, peu adapté à tous les usages),
on donne à l'utilisateur un fichier .txt prêt à coller dans son LLM préféré
(ChatGPT, Claude, Gemini, Mistral…). Il choisit lui-même le format final :
présentation PowerPoint, rapport Word, email, post LinkedIn, etc.

Avantage : zéro coût LLM côté ARGUS, flexibilité maximale côté utilisateur,
et le rendu final est toujours adapté au contexte du user.
"""

from datetime import datetime


def build_prompt(scan, assets, vulns, tls_findings,
                 surface_findings, tech_findings, score_data=None) -> str:
    """
    Construit un prompt structuré qui contient toutes les données du scan
    + des instructions claires pour qu'un LLM génère un livrable propre.

    `score_data` peut être None ou {"breakdown": [...]} — sert au contexte.
    """
    domain = scan.domain
    scan_date = scan.completed_at.strftime("%d/%m/%Y à %H:%M UTC") if scan.completed_at else "en cours"
    grade = scan.risk_grade or "?"
    score = scan.risk_score if scan.risk_score is not None else "?"

    lines = []

    # ─── Header / brief au LLM ──────────────────────────────────────
    lines.append("=" * 80)
    lines.append("INSTRUCTIONS POUR L'IA QUI REÇOIT CE PROMPT")
    lines.append("=" * 80)
    lines.append("")
    lines.append("Tu es un analyste cybersécurité senior. Tu reçois ci-dessous les")
    lines.append("résultats bruts d'un audit de reconnaissance externe (Web Attack")
    lines.append("Surface Management) réalisé par ARGUS Security sur un domaine.")
    lines.append("")
    lines.append("DEMANDE :")
    lines.append("Génère un livrable professionnel à partir de ces données. Format")
    lines.append("au choix de l'utilisateur (rapport exécutif, présentation PowerPoint,")
    lines.append("email client, post LinkedIn, etc.). Adapte le ton au public visé :")
    lines.append("- Dirigeant non-technique → langage business, focus risque opérationnel/financier")
    lines.append("- Équipe IT/DevOps → langage technique, plan d'action concret")
    lines.append("- Présentation commerciale → focus exemples de scénarios d'exploitation")
    lines.append("")
    lines.append("PRINCIPES À RESPECTER :")
    lines.append("- Ne JAMAIS banaliser : chaque sous-domaine exposé, chaque techno avec")
    lines.append("  version visible, chaque absence DMARC est une porte d'entrée potentielle.")
    lines.append("- Toujours donner au moins UN risque concret + scénario d'attaque réaliste.")
    lines.append("- Toujours conclure par 2-3 actions priorisées (verbes d'action).")
    lines.append("- Si tu suggères des outils de remédiation, cite uniquement des outils")
    lines.append("  reconnus (WAF Cloudflare, fail2ban, 2FA, VPN, etc.).")
    lines.append("- Ne mentionne PAS ARGUS Security comme \"outil de scan\" mais comme")
    lines.append("  \"analyste sécurité\" qui a livré le rapport.")
    lines.append("")
    lines.append("=" * 80)
    lines.append("DONNÉES BRUTES DU SCAN")
    lines.append("=" * 80)
    lines.append("")

    # ─── Métadonnées ───────────────────────────────────────────────
    lines.append("## CONTEXTE GÉNÉRAL")
    lines.append("")
    lines.append(f"Domaine audité : {domain}")
    lines.append(f"Date de l'audit : {scan_date}")
    lines.append(f"Score de risque ARGUS : {score}/100 (grade {grade})")
    lines.append(f"Mode pentest actif : {'Oui' if scan.pentest_authorized else 'Non — reconnaissance passive uniquement'}")
    lines.append("")

    # ─── Volumétrie ────────────────────────────────────────────────
    alive_count = sum(1 for a in assets if (a.status_code or 0) > 0)
    lines.append("## VOLUMÉTRIE")
    lines.append("")
    lines.append(f"- Actifs découverts : {len(assets)}")
    lines.append(f"- Actifs vivants (HTTP) : {alive_count}")
    lines.append(f"- Sous-domaines uniques : {len(scan.discovered_subs or [])}")
    lines.append(f"- Vulnérabilités détectées : {len(vulns)}")
    lines.append(f"- Vulnérabilités CRITIQUES (CISA KEV / EPSS≥50%) : {sum(1 for v in vulns if v.kev or (v.epss_score or 0) >= 0.5)}")
    lines.append("")

    # ─── Breakdown du score ────────────────────────────────────────
    if score_data and score_data.get("breakdown"):
        lines.append("## FACTEURS QUI ONT IMPACTÉ LE SCORE")
        lines.append("")
        for b in score_data["breakdown"]:
            delta = b.get("delta", 0)
            label = b.get("label", "")
            reason = b.get("reason", "")
            lines.append(f"- [{delta:+d} pts] {label} : {reason}")
        lines.append("")

    # ─── Surfaces sensibles ───────────────────────────────────────
    if surface_findings:
        lines.append("## SOUS-DOMAINES SENSIBLES DÉTECTÉS")
        lines.append("")
        lines.append("Chacun de ces sous-domaines a un nom suggérant un usage à risque")
        lines.append("(admin, backoffice, ancien, dev, test, etc.). Leur exposition")
        lines.append("publique est une porte d'entrée typique pour les attaquants.")
        lines.append("")
        for f in surface_findings:
            lines.append(f"### {f['host']} — SÉVÉRITÉ {f['severity'].upper()} — {f['label_short']}")
            lines.append(f"Pourquoi c'est un risque : {f['explanation']}")
            lines.append(f"Scénario d'exploitation : {f['scenario']}")
            lines.append(f"Action recommandée : {f['recommendation']}")
            lines.append("")

    # ─── Technologies à risque ────────────────────────────────────
    if tech_findings:
        lines.append("## TECHNOLOGIES IDENTIFIÉES À RISQUE")
        lines.append("")
        for f in tech_findings:
            tech_str = f"{f['tech']}"
            if f.get("version"):
                tech_str += f" v{f['version']}"
            if f.get("is_eol"):
                tech_str += " [VERSION EN FIN DE VIE]"
            lines.append(f"### {tech_str} — SÉVÉRITÉ {f['severity'].upper()}")
            lines.append(f"Pourquoi c'est un risque : {f['explanation']}")
            lines.append(f"Scénario d'exploitation : {f['scenario']}")
            lines.append(f"Action recommandée : {f['recommendation']}")
            lines.append("")

    # ─── Sécurité email (SPF/DKIM/DMARC) ─────────────────────────
    spf = scan.spf or {}
    dmarc = scan.dmarc or {}
    dkim = scan.dkim or {}
    if spf or dmarc or dkim:
        lines.append("## SÉCURITÉ EMAIL")
        lines.append("")
        if not spf.get("present"):
            lines.append("- SPF : ❌ ABSENT — spoofing email facilité")
        elif spf.get("policy") == "permissive":
            lines.append("- SPF : ⚠ POLITIQUE PERMISSIVE (+all) — n'importe qui peut spoofer")
        else:
            lines.append(f"- SPF : ✓ présent ({spf.get('policy', '?')})")
        if not dmarc.get("present"):
            lines.append("- DMARC : ❌ ABSENT — phishing au nom du domaine non bloqué")
        elif dmarc.get("policy") == "none":
            lines.append("- DMARC : ⚠ p=none (reporting seul, aucun blocage)")
        else:
            lines.append(f"- DMARC : ✓ présent ({dmarc.get('policy', '?')})")
        if not dkim.get("present"):
            lines.append("- DKIM : ⚠ non détecté sur les sélecteurs courants")
        else:
            lines.append("- DKIM : ✓ présent")
        lines.append("")

    # ─── TLS findings ────────────────────────────────────────────
    if tls_findings:
        expired = [t for t in tls_findings if t.expired]
        soon = [t for t in tls_findings if (t.days_until_expiry or 999) < 30 and not t.expired]
        if expired or soon:
            lines.append("## CERTIFICATS TLS / SSL — ALERTES")
            lines.append("")
            for t in expired:
                lines.append(f"- ❌ EXPIRÉ : {t.host}:{t.port} (expire le {t.not_after})")
            for t in soon:
                lines.append(f"- ⚠ EXPIRE BIENTÔT : {t.host}:{t.port} ({t.days_until_expiry} jours)")
            lines.append("")

    # ─── Vulnérabilités (CVE) ────────────────────────────────────
    if vulns:
        # Tri : KEV d'abord, puis EPSS élevé, puis severity
        sorted_vulns = sorted(
            vulns,
            key=lambda v: (
                1 if v.kev else 0,
                v.epss_score or 0,
                {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(v.severity, 0),
            ),
            reverse=True,
        )
        lines.append("## VULNÉRABILITÉS DÉTECTÉES (TOP 20 PRIORISÉES)")
        lines.append("")
        for v in sorted_vulns[:20]:
            sev = (v.severity or "?").upper()
            kev_tag = " [CISA KEV - EXPLOIT ACTIF]" if v.kev else ""
            epss_tag = f" [EPSS {int((v.epss_score or 0) * 100)}%]" if v.epss_score and v.epss_score >= 0.3 else ""
            cve = f" {v.cve_id}" if v.cve_id else ""
            lines.append(f"- [{sev}{kev_tag}{epss_tag}]{cve} {v.name}")
            if v.matched_url:
                lines.append(f"  URL : {v.matched_url}")
        if len(sorted_vulns) > 20:
            lines.append(f"  ... et {len(sorted_vulns) - 20} autres vulnérabilités")
        lines.append("")

    # ─── Liste des actifs vivants ────────────────────────────────
    if assets:
        alive_assets = [a for a in assets if (a.status_code or 0) > 0]
        if alive_assets:
            lines.append(f"## ACTIFS WEB VIVANTS ({len(alive_assets)} HTTP/HTTPS)")
            lines.append("")
            for a in alive_assets[:50]:
                techs = ", ".join(a.tech or [])
                title = (a.title or "")[:80]
                lines.append(f"- [{a.status_code}] {a.url}")
                if title:
                    lines.append(f"  Titre : {title}")
                if techs:
                    lines.append(f"  Technos : {techs}")
            if len(alive_assets) > 50:
                lines.append(f"  ... et {len(alive_assets) - 50} autres actifs")
            lines.append("")

    # ─── Sous-domaines découverts ────────────────────────────────
    if scan.discovered_subs:
        lines.append(f"## SOUS-DOMAINES DÉCOUVERTS ({len(scan.discovered_subs)})")
        lines.append("")
        for s in (scan.discovered_subs or [])[:80]:
            lines.append(f"- {s}")
        if len(scan.discovered_subs) > 80:
            lines.append(f"  ... et {len(scan.discovered_subs) - 80} autres")
        lines.append("")

    # ─── Footer — variations possibles ───────────────────────────
    lines.append("=" * 80)
    lines.append("VARIATIONS POSSIBLES DU LIVRABLE (à demander à l'IA selon le besoin)")
    lines.append("=" * 80)
    lines.append("")
    lines.append("1. Rapport exécutif Word (3 pages, langage business)")
    lines.append("2. Présentation PowerPoint (10 slides, focus risques + actions)")
    lines.append("3. Email résumé pour le DSI (200 mots, top 3 actions urgentes)")
    lines.append("4. Post LinkedIn (300 caractères, sensibiliser sans technique)")
    lines.append("5. Plan de remédiation détaillé (markdown, par criticité)")
    lines.append("6. Ticket Jira/Github par finding (un par vulnérabilité critique)")
    lines.append("7. Brief pour réunion équipe IT (1 page, technique mais accessible)")
    lines.append("")
    lines.append("─" * 80)
    lines.append(f"Généré par ARGUS Security le {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}")
    lines.append("ARGUS Security · Reconnaissance offensive · https://argusanalyzer.com")
    lines.append("─" * 80)

    return "\n".join(lines)
