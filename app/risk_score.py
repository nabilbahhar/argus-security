"""
risk_score.py — Le "ARGUS Risk Score" (0 à 100)

C'est LA métrique unique qui résume tout. Inspirée :
  - Mozilla Observatory (note A+ à F)
  - Score F de Purplemet (cité par Benjamin Krown)
  - Score Snyk, Wiz, etc.

But : permettre à un CISO non-tech de COMPRENDRE en 5 secondes
si son domaine est OK ou non.

Échelle :
  - 90-100 = A   (excellent, posture exemplaire)
  - 75-89  = B   (correct, quelques points faibles)
  - 60-74  = C   (moyen, action recommandée)
  - 40-59  = D   (mauvais, action urgente)
  - 0-39   = F   (critique, fuite la maison brûle)
"""

import re

SENSITIVE_PORTS = {
    21: "FTP", 23: "Telnet", 445: "SMB", 1433: "SQL Server", 1521: "Oracle",
    2375: "Docker", 3306: "MySQL", 3389: "bureau à distance", 5432: "PostgreSQL",
    5900: "VNC", 5984: "CouchDB", 6379: "Redis", 9200: "Elasticsearch",
    11211: "Memcached", 27017: "MongoDB",
}
SENSITIVE_PATH_RE = re.compile(
    r"^\.(env|git|svn|hg|ds_store)|\.(sql|bak|log)$|backup|dump|wp-config|phpinfo|^info\.php"
    r"|actuator/env|server-(status|info)|elmah\.axd|trace\.axd|credentials|passwords?$|secrets?$",
    re.I,
)


def compute_score(scan_data: dict) -> dict:
    """
    Calcule le score à partir des findings du scan.

    Args:
        scan_data: dict avec clés "assets", "vulns" (enrichies EPSS/KEV),
                   "dns" (résultat dns_scan), "tls" (liste tls_scan),
                   "hostnames" (liste subdomains découverts), "domain" (root),
                   "pentest" (ports et chemins trouvés en mode actif)

    Returns:
        {
            "score": 73,
            "grade": "C",
            "breakdown": [
                {"label": "Email security", "delta": -15, "reason": "Pas de DMARC"},
                ...
            ]
        }
    """
    from app.surface_risk import analyze_surface, score_impact as surface_score_impact
    from app.tech_insights import analyze_techs, score_impact as tech_score_impact
    from app.headers_scan import analyze_headers, score_impact as headers_score_impact

    score = 100.0
    breakdown: list[dict] = []

    assets = scan_data.get("assets") or []
    vulns = scan_data.get("vulns") or []
    dns = scan_data.get("dns") or {}
    tls_findings = scan_data.get("tls") or []
    hostnames = scan_data.get("hostnames") or []
    root_domain = scan_data.get("domain") or ""
    pentest = scan_data.get("pentest") or {}

    # ── Vulnérabilités Nuclei ──
    critical = [v for v in vulns if (v.get("severity") or "").lower() == "critical"]
    high = [v for v in vulns if (v.get("severity") or "").lower() == "high"]
    medium = [v for v in vulns if (v.get("severity") or "").lower() == "medium"]
    low = [v for v in vulns if (v.get("severity") or "").lower() == "low"]
    kev_vulns = [v for v in vulns if v.get("kev")]
    high_epss = [v for v in vulns if (v.get("epss_score") or 0) >= 0.5]

    if kev_vulns:
        delta = -min(30, 12 * len(kev_vulns))
        score += delta
        breakdown.append({
            "label": "KEV — vulnérabilités activement exploitées",
            "delta": delta,
            "reason": f"{len(kev_vulns)} CVE listée(s) au catalogue CISA KEV : exploitation en cours dans le monde",
        })

    if high_epss:
        delta = -min(20, 4 * len(high_epss))
        score += delta
        breakdown.append({
            "label": "EPSS — vulnérabilités à forte probabilité d'exploitation",
            "delta": delta,
            "reason": f"{len(high_epss)} CVE avec EPSS ≥ 50% (probabilité d'exploitation dans 30 jours)",
        })

    if critical:
        # On évite de double-compter si déjà KEV
        non_kev = [v for v in critical if not v.get("kev")]
        if non_kev:
            delta = -min(25, 8 * len(non_kev))
            score += delta
            breakdown.append({
                "label": "Vulnérabilités critiques",
                "delta": delta,
                "reason": f"{len(non_kev)} CVE critique(s) non encore listée(s) KEV",
            })

    if high:
        delta = -min(15, 3 * len(high))
        score += delta
        breakdown.append({
            "label": "Vulnérabilités élevées",
            "delta": delta,
            "reason": f"{len(high)} finding(s) sévérité haute",
        })

    if medium:
        delta = -min(10, 1.5 * len(medium))
        score += delta
        breakdown.append({
            "label": "Vulnérabilités moyennes",
            "delta": int(delta),
            "reason": f"{len(medium)} finding(s) sévérité moyenne",
        })

    if low:
        delta = -min(5, len(low))
        score += delta
        breakdown.append({
            "label": "Vulnérabilités faibles",
            "delta": delta,
            "reason": f"{len(low)} finding(s) sévérité faible",
        })

    # ── DNS / Email security ──
    spf = dns.get("spf", {})
    dmarc = dns.get("dmarc", {})
    dkim = dns.get("dkim", {})

    if not spf.get("present"):
        score -= 8
        breakdown.append({
            "label": "SPF absent",
            "delta": -8,
            "reason": "Aucun SPF publié → spoofing email facilité",
        })
    elif spf.get("policy") == "permissive":
        score -= 10
        breakdown.append({
            "label": "SPF en +all",
            "delta": -10,
            "reason": "Politique SPF permissive (+all) : N'IMPORTE QUI peut spoofer",
        })

    if not dmarc.get("present"):
        score -= 12
        breakdown.append({
            "label": "DMARC absent",
            "delta": -12,
            "reason": "Aucun DMARC publié → phishing au nom du domaine non bloqué",
        })
    elif dmarc.get("policy") == "none":
        score -= 6
        breakdown.append({
            "label": "DMARC en p=none",
            "delta": -6,
            "reason": "DMARC en mode reporting seul → aucun blocage des spoofings",
        })

    if not dkim.get("present"):
        score -= 5
        breakdown.append({
            "label": "DKIM non détecté",
            "delta": -5,
            "reason": "Aucun DKIM publié sur les sélecteurs courants",
        })

    records = dns.get("records") or {}
    if records and not records.get("CAA"):
        score -= 2
        breakdown.append({
            "label": "CAA absent",
            "delta": -2,
            "reason": "Aucune restriction sur les autorités pouvant émettre un certificat pour ce domaine",
        })

    # ── TLS / SSL health ──
    expired = [t for t in tls_findings if t.get("expired")]
    soon = [t for t in tls_findings if (t.get("days_until_expiry") or 999) < 30 and not t.get("expired")]
    weak = [t for t in tls_findings if any("obsolètes" in i for i in (t.get("issues") or []))]

    if expired:
        delta = -min(20, 8 * len(expired))
        score += delta
        breakdown.append({
            "label": "Certificats TLS expirés",
            "delta": delta,
            "reason": f"{len(expired)} certificat(s) expiré(s) → navigateurs bloquent l'accès",
        })
    if soon:
        delta = -min(10, 2 * len(soon))
        score += delta
        breakdown.append({
            "label": "Certificats TLS expirant bientôt",
            "delta": delta,
            "reason": f"{len(soon)} certificat(s) expirent dans les 30 jours",
        })
    invalid = [t for t in tls_findings if t.get("self_signed") or t.get("mismatched") or t.get("untrusted")]
    if invalid:
        delta = -min(15, 4 * len(invalid))
        score += delta
        breakdown.append({
            "label": "Certificats TLS invalides",
            "delta": delta,
            "reason": f"{len(invalid)} certificat(s) auto-signé(s), non reconnu(s) ou au mauvais nom → alerte navigateur, interception facilitée",
        })
    if weak:
        delta = -min(8, 2 * len(weak))
        score += delta
        breakdown.append({
            "label": "Protocoles TLS obsolètes",
            "delta": delta,
            "reason": f"{len(weak)} actif(s) supportent TLS 1.0/1.1/SSL → MITM possible",
        })

    # ── Mode actif : services et fichiers réellement accessibles ──
    open_services = {
        (p.get("host"), p["port"]) for p in pentest.get("ports") or [] if p.get("port") in SENSITIVE_PORTS
    }
    if open_services:
        delta = -min(20, 6 * len(open_services))
        names = sorted({SENSITIVE_PORTS[port] for _, port in open_services})
        score += delta
        breakdown.append({
            "label": "Services sensibles exposés",
            "delta": delta,
            "reason": f"{len(open_services)} service(s) accessible(s) depuis Internet : {', '.join(names)}",
        })

    exposed_paths = {
        p.get("url") for p in pentest.get("paths") or []
        if p.get("status") == 200 and SENSITIVE_PATH_RE.search(p.get("matched") or "")
    }
    if exposed_paths:
        delta = -min(25, 8 * len(exposed_paths))
        score += delta
        breakdown.append({
            "label": "Fichiers sensibles accessibles",
            "delta": delta,
            "reason": f"{len(exposed_paths)} fichier(s) ou page(s) sensible(s) lisible(s) sans authentification",
        })

    # ── Exposition de surface ──
    alive = [a for a in assets if a.get("status_code", 0) > 0]
    if len(alive) > 50:
        score -= 3
        breakdown.append({
            "label": "Surface d'attaque large",
            "delta": -3,
            "reason": f"{len(alive)} actifs vivants — beaucoup à surveiller",
        })

    # ── Patterns de sous-domaines à risque (bo, admin, old, dev…) ──
    surface_analysis = analyze_surface(hostnames, root_domain) if hostnames else {"findings": [], "stats": {}}
    s_delta, s_reason = surface_score_impact(surface_analysis["stats"])
    if s_delta < 0:
        score += s_delta
        breakdown.append({
            "label": "Surfaces sensibles exposées",
            "delta": s_delta,
            "reason": s_reason,
        })

    # ── Technologies exposées avec versions (PHP, WordPress, nginx…) ──
    all_techs = []
    for a in assets:
        all_techs.extend(a.get("tech") or [])
    tech_analysis = analyze_techs(all_techs) if all_techs else {"findings": [], "stats": {}}
    t_delta, t_reason = tech_score_impact(tech_analysis["stats"])
    if t_delta < 0:
        score += t_delta
        breakdown.append({
            "label": "Technologies exposées à risque",
            "delta": t_delta,
            "reason": t_reason,
        })

    # ── Protections HTTP (headers, cookies, CORS) ──
    h_delta, h_reason = headers_score_impact(analyze_headers(assets)["stats"])
    if h_delta < 0:
        score += h_delta
        breakdown.append({
            "label": "Protections HTTP insuffisantes",
            "delta": h_delta,
            "reason": h_reason,
        })

    # Borne 0-100
    score = max(0, min(100, int(round(score))))

    # Grade
    if score >= 90:
        grade, color = "A", "neon-green"
    elif score >= 75:
        grade, color = "B", "neon-cyan"
    elif score >= 60:
        grade, color = "C", "neon-yellow"
    elif score >= 40:
        grade, color = "D", "sev-high"
    else:
        grade, color = "F", "sev-critical"

    return {
        "score": score,
        "grade": grade,
        "color": color,
        "breakdown": breakdown,
        # Findings détaillés pour le template (utilisés directement par scan.html)
        "surface_findings": surface_analysis.get("findings", []),
        "tech_findings": tech_analysis.get("findings", []),
    }
