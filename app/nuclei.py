"""
nuclei.py — Scanner de vulnérabilités CVE + misconfigs

Sprint 1 : Nuclei basique avec severity filter.
Sprint 1.5 : Couverture élargie via TAGS Nuclei :
  - exposures   : fichiers sensibles exposés (.env, .git, backups)
  - misconfig   : mauvaises configurations (CORS, headers, debug pages)
  - takeover    : subdomain takeover (CNAME pointant vers service abandonné)
  - default-logins : credentials par défaut sur panels admin
  - cve         : vulnérabilités CVE classiques
  - panel       : panneaux d'admin exposés (jenkins, phpmyadmin, etc.)

C'est ce qui permet à ARGUS de détecter les "low-hanging fruits"
que CyCognito et Censys ratent ou affichent mal (cf. gap analysis).
"""

import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).parent.parent
NUCLEI = ROOT / "tools" / "bin" / "nuclei.exe"

# Tags activés par défaut — couverture large mais ciblée "trouvable de l'extérieur"
DEFAULT_TAGS = [
    "cve",            # CVE classiques
    "exposure",       # fichiers sensibles exposés
    "misconfig",      # mauvaises configurations
    "takeover",       # subdomain takeover
    "default-logins", # creds par défaut
    "panel",          # panneaux admin exposés
    "tech",           # techno-fingerprint findings
]


def run_nuclei(
    urls: list[str],
    severity: str = "critical,high,medium",
    tags: list[str] | None = None,
    timeout: int = 1800,
    rate_limit: int = 150,
) -> list[dict]:
    """
    Lance nuclei sur une liste d'URLs et retourne les findings.

    Args:
        urls       : URLs à tester (sortie httpx alive)
        severity   : sévérités à inclure
        tags       : tags Nuclei à exécuter (défaut = couverture large)
        timeout    : max temps total
        rate_limit : requêtes/seconde

    NOTE : la 1ère fois, Nuclei télécharge ~12k templates (~150 Mo).
    """
    if not NUCLEI.exists():
        raise FileNotFoundError(f"nuclei.exe manquant : {NUCLEI}")
    if not urls:
        return []

    tags = tags or DEFAULT_TAGS
    input_text = "\n".join(urls)

    result = subprocess.run(
        [
            str(NUCLEI),
            "-jsonl",
            "-severity", severity,
            "-tags", ",".join(tags),
            "-no-color",
            "-silent",
            "-rate-limit", str(rate_limit),
            "-timeout", "10",
            "-duc",           # disable update check
            "-stats", "false",
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

        info = entry.get("info", {}) or {}
        classification = info.get("classification", {}) or {}
        cve_ids = classification.get("cve-id", []) or []
        cve = cve_ids[0] if cve_ids else None

        findings.append({
            "template_id": entry.get("template-id", ""),
            "name": info.get("name", ""),
            "description": info.get("description", ""),
            "severity": (info.get("severity") or "info").lower(),
            "matched_url": entry.get("matched-at", "") or entry.get("host", ""),
            "cve_id": cve,
            "reference": info.get("reference", []) or [],
            "extracted_results": entry.get("extracted-results", []) or [],
            "tags": info.get("tags", []) or [],
        })

    return findings


def severity_score(severity: str) -> int:
    return {
        "critical": 100,
        "high": 75,
        "medium": 50,
        "low": 25,
        "info": 10,
    }.get(severity.lower(), 0)


def vuln_priority_score(vuln: dict) -> int:
    """
    Score combiné pour trier les vulns :
    - +1000 si KEV (= activement exploitée)
    - + EPSS * 500 (probabilité d'exploitation)
    - + severity_score (gravité statique)

    Ex : une medium avec KEV peut passer devant une critical sans KEV.
    """
    sev = severity_score(vuln.get("severity") or "")
    epss = (vuln.get("epss_score") or 0) * 500
    kev = 1000 if vuln.get("kev") else 0
    return int(kev + epss + sev)
