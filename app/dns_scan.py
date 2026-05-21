"""
dns_scan.py — Audit DNS + Email Security (SPF / DKIM / DMARC)

EXEMPLE concret de pourquoi c'est critique :
  Si le domaine compucom.ma n'a pas de DMARC publié, n'importe qui peut
  envoyer un email "facture@compucom.ma" depuis n'importe quel serveur,
  qui passera les filtres Gmail/Outlook. C'est l'origine de 95% des phishings
  qui réussissent. C'est la 1ère chose qu'un CISO veut savoir.
"""

from __future__ import annotations
import dns.resolver
import dns.exception

DEFAULT_DKIM_SELECTORS = [
    "default", "google", "k1", "mail", "selector1", "selector2",
    "smtp", "mailgun", "mandrill", "sendgrid", "zoho", "pm", "amazonses",
]


def _query(domain: str, rtype: str, timeout: float = 5.0) -> list[str]:
    """Résout un type DNS. Retourne liste de strings, vide en cas d'erreur."""
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout
        answers = resolver.resolve(domain, rtype)
        return [a.to_text().strip().strip('"') for a in answers]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
            dns.exception.DNSException, dns.resolver.NoNameservers):
        return []


def _parse_spf(txt_records: list[str]) -> dict:
    """Parse les TXT records pour trouver le SPF et son verdict."""
    spf_record = next((r for r in txt_records if r.lower().startswith("v=spf1")), None)
    if not spf_record:
        return {"present": False, "policy": None, "raw": None, "issue": "Aucun SPF publié"}

    # Politique finale : -all (strict), ~all (soft), ?all (neutral), +all (permissif)
    lower = spf_record.lower()
    if "-all" in lower:
        policy, issue = "strict", None
    elif "~all" in lower:
        policy, issue = "soft", "SPF en mode soft (~all) — préférer -all pour anti-spoofing strict"
    elif "?all" in lower:
        policy, issue = "neutral", "SPF en mode neutral (?all) — équivalent à pas de protection"
    elif "+all" in lower:
        policy, issue = "permissive", "⚠ SPF en mode +all : N'IMPORTE QUI peut spoofer ce domaine"
    else:
        policy, issue = "no-all", "SPF sans directive 'all' — protection incomplète"

    return {"present": True, "policy": policy, "raw": spf_record, "issue": issue}


def _parse_dmarc(domain: str) -> dict:
    """Lit _dmarc.<domain> et parse la policy."""
    records = _query(f"_dmarc.{domain}", "TXT")
    dmarc_record = next((r for r in records if r.lower().startswith("v=dmarc1")), None)
    if not dmarc_record:
        return {"present": False, "policy": None, "raw": None, "issue": "Aucun DMARC publié → spoofing trivial"}

    parts = {p.split("=")[0].strip().lower(): p.split("=", 1)[1].strip() if "=" in p else ""
             for p in dmarc_record.split(";") if p.strip()}
    policy = parts.get("p", "none").lower()

    if policy == "reject":
        issue = None
    elif policy == "quarantine":
        issue = "DMARC en quarantine — préférer p=reject pour blocage strict"
    else:
        issue = "DMARC en p=none → reporting seul, aucun blocage des spoofings"

    return {"present": True, "policy": policy, "raw": dmarc_record, "issue": issue}


def _detect_dkim(domain: str, selectors: list[str] | None = None) -> dict:
    """Cherche les sélecteurs DKIM connus."""
    selectors = selectors or DEFAULT_DKIM_SELECTORS
    found = []
    for sel in selectors:
        records = _query(f"{sel}._domainkey.{domain}", "TXT")
        for r in records:
            if "v=dkim1" in r.lower() or "k=rsa" in r.lower() or "p=" in r.lower():
                found.append({"selector": sel, "raw": r[:200]})
                break

    if found:
        return {"present": True, "selectors": found, "issue": None}
    return {
        "present": False,
        "selectors": [],
        "issue": "Aucun DKIM détecté sur les sélecteurs courants (peut exister sur un sélecteur custom)",
    }


def scan_dns(domain: str) -> dict:
    """
    Audit DNS complet pour un domaine.

    Returns:
        {
            "records": {"A": [...], "AAAA": [...], "MX": [...], "NS": [...], "TXT": [...]},
            "spf":    {"present": True, "policy": "strict", "issue": None},
            "dmarc":  {"present": False, "issue": "Aucun DMARC..."},
            "dkim":   {"present": True, "selectors": [...]},
            "issues": [list of strings],  # tous les problèmes pour scoring
        }
    """
    records = {
        "A": _query(domain, "A"),
        "AAAA": _query(domain, "AAAA"),
        "MX": _query(domain, "MX"),
        "NS": _query(domain, "NS"),
        "TXT": _query(domain, "TXT"),
        "CAA": _query(domain, "CAA"),
    }

    spf = _parse_spf(records["TXT"])
    dmarc = _parse_dmarc(domain)
    dkim = _detect_dkim(domain)

    issues = []
    if spf["issue"]:
        issues.append(f"SPF : {spf['issue']}")
    if dmarc["issue"]:
        issues.append(f"DMARC : {dmarc['issue']}")
    if dkim["issue"]:
        issues.append(f"DKIM : {dkim['issue']}")
    if not records["CAA"]:
        issues.append("CAA : Aucune restriction émetteurs de certificats — un acteur compromis peut émettre des certs au nom du domaine")

    return {
        "records": records,
        "spf": spf,
        "dmarc": dmarc,
        "dkim": dkim,
        "issues": issues,
    }
