"""
tls_scan.py — Audit TLS/SSL des actifs web

Utilise le binaire `tlsx` de ProjectDiscovery pour analyser :
  - Validité du certificat (date d'expiration, autosignature)
  - Protocoles supportés (TLS 1.0/1.1 = obsolètes, TLS 1.3 = idéal)
  - Cipher suites (faibles = vulnérables MITM)
  - Subject Alternative Names (SAN) → révèle d'autres domaines cachés

EXEMPLE de risque : certificat expiré sur compucom.ma → Chrome bloque l'accès →
les visiteurs voient "Site dangereux" → perte directe de chiffre d'affaires.
"""

import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).parent.parent
TLSX = ROOT / "tools" / "bin" / "tlsx.exe"

# Protocoles considérés faibles/obsolètes
DEPRECATED_PROTOCOLS = {"sslv2", "sslv3", "tls10", "tls11"}


def run_tlsx(urls: list[str], timeout: int = 300) -> list[dict]:
    """
    Lance tlsx sur une liste d'URLs et retourne les findings TLS.

    Args:
        urls: URLs à analyser (sortie httpx alive)
        timeout: max temps total

    Returns:
        Liste de dicts avec : host, cert validity, ciphers, protocols, SANs, issues.
    """
    if not TLSX.exists():
        return []
    if not urls:
        return []

    # On extrait les hosts pour tlsx (qui prend host:port, pas URL)
    hosts = []
    for u in urls:
        h = u.replace("https://", "").replace("http://", "").split("/")[0]
        if ":" not in h:
            h = h + ":443"
        hosts.append(h)

    input_text = "\n".join(hosts)
    result = subprocess.run(
        [
            str(TLSX),
            "-json",
            "-silent",
            "-cert",       # détails du certificat
            "-cipher",     # cipher suites
            "-tls-version",  # protocoles supportés
            "-san",        # subject alternative names
            "-expired",    # flag si expiré
            "-self-signed", # flag si auto-signé
            "-untrusted",  # flag si CA inconnue
            "-mismatched", # flag si hostname mismatch
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
        except json.JSONDecodeError:
            continue

        # Date d'expiration
        not_after_str = entry.get("not_after", "") or ""
        days_until_expiry = None
        try:
            # tlsx peut renvoyer plusieurs formats
            not_after = datetime.fromisoformat(not_after_str.replace("Z", "+00:00"))
            days_until_expiry = (not_after - datetime.now(timezone.utc)).days
        except (ValueError, AttributeError):
            pass

        # Issues détectées
        issues = []
        if entry.get("expired"):
            issues.append("Certificat EXPIRÉ — navigateurs bloquent l'accès")
        elif days_until_expiry is not None and days_until_expiry < 30:
            issues.append(f"Certificat expire dans {days_until_expiry} jours")
        if entry.get("self_signed"):
            issues.append("Certificat auto-signé — non reconnu par les navigateurs")
        if entry.get("untrusted"):
            issues.append("Autorité de certification non reconnue")
        if entry.get("mismatched"):
            issues.append("Le nom du certificat ne correspond pas au domaine")

        # Protocoles faibles
        versions = entry.get("tls_version") or entry.get("versions") or []
        if isinstance(versions, str):
            versions = [versions]
        deprecated = [v for v in versions if v.lower() in DEPRECATED_PROTOCOLS]
        if deprecated:
            issues.append(f"Protocoles obsolètes supportés : {', '.join(deprecated)} — vulnérables MITM")

        findings.append({
            "host": entry.get("host", ""),
            "port": entry.get("port", 443),
            "issuer": entry.get("issuer_org", [""])[0] if isinstance(entry.get("issuer_org"), list) else entry.get("issuer_dn", ""),
            "subject_cn": entry.get("subject_cn", ""),
            "subject_an": entry.get("subject_an", []),
            "not_before": entry.get("not_before", ""),
            "not_after": not_after_str,
            "days_until_expiry": days_until_expiry,
            "tls_versions": versions,
            "cipher": entry.get("cipher", ""),
            "self_signed": bool(entry.get("self_signed")),
            "expired": bool(entry.get("expired")),
            "mismatched": bool(entry.get("mismatched")),
            "issues": issues,
        })

    return findings
