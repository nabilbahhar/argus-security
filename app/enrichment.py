"""
enrichment.py — Enrichissement des vulnérabilités CVE avec EPSS + CISA KEV

C'EST CE QUI DIFFÉRENCIE ARGUS de la concurrence.

EXEMPLE concret (cité par Benjamin Krown dans son email d'avril 2025) :
  "9 URLs ont obtenu un score F avec plusieurs dizaines de CVE ayant des
   scores EPSS (probabilité d'exploitation) élevés (>90%) et des KEV
   (exploits connus pour la CVE)"

  => ARGUS va plus loin : pour CHAQUE vuln Nuclei, on enrichit avec :
       - EPSS : probabilité d'exploitation dans les 30 jours (FIRST.org)
       - KEV  : la CVE est-elle dans le catalogue "Known Exploited Vulnerabilities"
                de la CISA (= les attaquants l'utilisent ACTIVEMENT contre des entreprises)

SOURCES :
  - EPSS : https://api.first.org/data/v1/epss?cve=CVE-2024-XXXXX
  - KEV  : https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
"""

from __future__ import annotations
import json
import time
from datetime import datetime, timedelta
from pathlib import Path
import httpx

ROOT = Path(__file__).parent.parent
CACHE_DIR = ROOT / "data" / "cache"
CACHE_DIR.mkdir(parents=True, exist_ok=True)

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_CACHE = CACHE_DIR / "kev_catalog.json"
KEV_CACHE_TTL_HOURS = 24

EPSS_API = "https://api.first.org/data/v1/epss"
EPSS_CACHE = CACHE_DIR / "epss_cache.json"
EPSS_CACHE_TTL_HOURS = 12


# ─────────────────────────────────────────────────────────
# KEV (CISA Known Exploited Vulnerabilities)
# ─────────────────────────────────────────────────────────

def _load_kev_catalog() -> set[str]:
    """
    Charge le catalogue KEV (cache 24h).
    Retourne un set de CVE IDs qui sont activement exploitées dans le monde.
    """
    # Cache valide ?
    if KEV_CACHE.exists():
        age_hours = (datetime.utcnow() - datetime.fromtimestamp(KEV_CACHE.stat().st_mtime)).total_seconds() / 3600
        if age_hours < KEV_CACHE_TTL_HOURS:
            try:
                data = json.loads(KEV_CACHE.read_text(encoding="utf-8"))
                return set(v["cveID"] for v in data.get("vulnerabilities", []))
            except (json.JSONDecodeError, KeyError):
                pass

    # Sinon on télécharge
    try:
        with httpx.Client(timeout=30.0, follow_redirects=True) as client:
            resp = client.get(KEV_URL)
            resp.raise_for_status()
            data = resp.json()
            KEV_CACHE.write_text(json.dumps(data), encoding="utf-8")
            return set(v["cveID"] for v in data.get("vulnerabilities", []))
    except Exception:
        # En cas d'échec réseau, on retourne un set vide (= on n'affichera juste pas le KEV)
        return set()


def is_kev(cve_id: str, kev_set: set[str] | None = None) -> bool:
    """Vrai si la CVE est activement exploitée selon CISA."""
    if not cve_id:
        return False
    if kev_set is None:
        kev_set = _load_kev_catalog()
    return cve_id.upper() in kev_set


# ─────────────────────────────────────────────────────────
# EPSS (Exploit Prediction Scoring System — FIRST.org)
# ─────────────────────────────────────────────────────────

def _load_epss_cache() -> dict[str, dict]:
    """Charge le cache local des scores EPSS."""
    if not EPSS_CACHE.exists():
        return {}
    try:
        return json.loads(EPSS_CACHE.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}


def _save_epss_cache(cache: dict[str, dict]) -> None:
    EPSS_CACHE.write_text(json.dumps(cache), encoding="utf-8")


def get_epss_scores(cve_ids: list[str]) -> dict[str, dict]:
    """
    Récupère les scores EPSS pour une liste de CVEs.
    EPSS donne une probabilité (0.0 à 1.0) que la CVE soit exploitée dans les 30 prochains jours.

    Returns:
        {"CVE-2024-XXXX": {"epss": 0.945, "percentile": 0.99, "date": "2026-05-18"}}
    """
    if not cve_ids:
        return {}

    # Filter to valid-looking CVE IDs and dedup
    cves = sorted({c.upper() for c in cve_ids if c and c.upper().startswith("CVE-")})
    if not cves:
        return {}

    cache = _load_epss_cache()
    now = datetime.utcnow()
    result: dict[str, dict] = {}
    to_fetch: list[str] = []

    for cve in cves:
        cached = cache.get(cve)
        if cached and "fetched_at" in cached:
            age_hours = (now - datetime.fromisoformat(cached["fetched_at"])).total_seconds() / 3600
            if age_hours < EPSS_CACHE_TTL_HOURS:
                result[cve] = {
                    "epss": cached.get("epss"),
                    "percentile": cached.get("percentile"),
                    "date": cached.get("date"),
                }
                continue
        to_fetch.append(cve)

    # Fetch en batch (l'API accepte 100 CVE par requête)
    if to_fetch:
        BATCH = 100
        try:
            with httpx.Client(timeout=20.0, follow_redirects=True) as client:
                for i in range(0, len(to_fetch), BATCH):
                    batch = to_fetch[i:i + BATCH]
                    resp = client.get(EPSS_API, params={"cve": ",".join(batch)})
                    resp.raise_for_status()
                    data = resp.json()
                    for entry in data.get("data", []):
                        cve = entry["cve"].upper()
                        try:
                            epss = float(entry.get("epss", 0))
                            percentile = float(entry.get("percentile", 0))
                        except (TypeError, ValueError):
                            continue
                        result[cve] = {
                            "epss": epss,
                            "percentile": percentile,
                            "date": entry.get("date", ""),
                        }
                        cache[cve] = {
                            **result[cve],
                            "fetched_at": now.isoformat(),
                        }
                    time.sleep(0.3)  # gentle rate limiting
            _save_epss_cache(cache)
        except Exception:
            pass  # silencieux : si offline on retourne juste ce qu'on a en cache

    return result


# ─────────────────────────────────────────────────────────
# Enrich vulns
# ─────────────────────────────────────────────────────────

def enrich_vulns(vulns: list[dict]) -> list[dict]:
    """
    Pour chaque vuln avec un cve_id, ajoute epss_score (0-1) et kev (bool).
    Modifie en place ET retourne la liste.
    """
    cve_ids = [v.get("cve_id") for v in vulns if v.get("cve_id")]
    if not cve_ids:
        return vulns

    kev_set = _load_kev_catalog()
    epss_scores = get_epss_scores(cve_ids)

    for v in vulns:
        cve = (v.get("cve_id") or "").upper()
        if not cve:
            continue
        epss_data = epss_scores.get(cve)
        if epss_data:
            v["epss_score"] = epss_data.get("epss")
            v["epss_percentile"] = epss_data.get("percentile")
        v["kev"] = is_kev(cve, kev_set)

    return vulns
