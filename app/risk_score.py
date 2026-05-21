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


def compute_score(scan_data: dict) -> dict:
    """
    Calcule le score à partir des findings du scan.

    Args:
        scan_data: dict avec clés "assets", "vulns" (enrichies EPSS/KEV),
                   "dns" (résultat dns_scan), "tls" (liste tls_scan)

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
    score = 100.0
    breakdown: list[dict] = []

    assets = scan_data.get("assets") or []
    vulns = scan_data.get("vulns") or []
    dns = scan_data.get("dns") or {}
    tls_findings = scan_data.get("tls") or []

    # ── Vulnérabilités Nuclei ──
    critical = [v for v in vulns if (v.get("severity") or "").lower() == "critical"]
    high = [v for v in vulns if (v.get("severity") or "").lower() == "high"]
    medium = [v for v in vulns if (v.get("severity") or "").lower() == "medium"]
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
    if weak:
        delta = -min(8, 2 * len(weak))
        score += delta
        breakdown.append({
            "label": "Protocoles TLS obsolètes",
            "delta": delta,
            "reason": f"{len(weak)} actif(s) supportent TLS 1.0/1.1/SSL → MITM possible",
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
    }
