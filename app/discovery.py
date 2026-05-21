"""
discovery.py — Orchestrateur multi-sources de découverte de sous-domaines

Sprint 2.0 "Discovery MAX" : combine 5 stratégies pour MAXIMISER la couverture.

PIPELINE :
  1. subfinder        (30+ sources OSINT free de ProjectDiscovery)
  2. Certificate Transparency direct (crt.sh) — souvent + exhaustif
  3. Wayback Machine  (archive.org) — sous-domaines historiques (parfois takeover-able)
  4. DNS brute force  (wordlist 200+ noms communs : admin, vpn, api, staging, etc.)
  5. IA permutation   (Claude analyse les patterns trouvés et génère des variantes)

But : passer de ~14% du parc Purplemet à 100%+ sur le même domaine.

Sources sans clé API requise (= marche dès le 1er scan).
Les sources premium (Shodan, SecurityTrails, etc.) sont possibles via la config
subfinder (~/AppData/Roaming/subfinder/provider-config.yaml) si l'utilisateur ajoute
ses clés.
"""

from __future__ import annotations
import json
import os
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
import httpx

# ─────────────────────────────────────────────────────────────
# Source 1 : Certificate Transparency (crt.sh)
# ─────────────────────────────────────────────────────────────

def fetch_crtsh(domain: str, timeout: float = 90.0) -> set[str]:
    """
    Récupère TOUS les sous-domaines présents dans les logs de certificats SSL/TLS publics.

    Comment ça marche : chaque fois qu'une autorité de certification (Let's Encrypt,
    DigiCert, Sectigo...) émet un certificat, c'est publié dans des "Certificate
    Transparency logs" publics. crt.sh indexe ça. On query avec %.domain.com et on
    récupère tous les CN/SAN historiques.

    Souvent + exhaustif que subfinder car remonte aussi les sous-domaines internes
    qui ont reçu un cert (même temporairement).
    """
    subs: set[str] = set()
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        with httpx.Client(timeout=timeout, follow_redirects=True) as client:
            resp = client.get(url, headers={"User-Agent": "ARGUS-Scanner/0.2"})
            if resp.status_code != 200:
                return subs
            # crt.sh peut renvoyer NDJSON ou JSON array. On gère les 2.
            text = resp.text.strip()
            try:
                data = json.loads(text)
            except json.JSONDecodeError:
                # NDJSON line-by-line
                data = []
                for line in text.splitlines():
                    if line.strip():
                        try:
                            data.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue
            for entry in data:
                names = entry.get("name_value", "") or ""
                for raw in names.replace("\\n", "\n").split("\n"):
                    name = raw.strip().lower().lstrip("*.").rstrip(".")
                    # Filtre : doit terminer par le domaine cible
                    if name and (name == domain or name.endswith("." + domain)):
                        subs.add(name)
    except Exception:
        pass
    return subs


# ─────────────────────────────────────────────────────────────
# Source 2 : Wayback Machine (archive.org)
# ─────────────────────────────────────────────────────────────

def fetch_wayback(domain: str, timeout: float = 120.0, limit: int = 5000) -> set[str]:
    """
    Récupère les sous-domaines HISTORIQUES depuis l'archive web mondiale.

    Ce que ça apporte d'unique :
      - Sous-domaines anciens, abandonnés mais qui répondent toujours
      - Souvent vulnérables (versions logicielles obsolètes)
      - Candidats prime aux subdomain takeovers
    """
    subs: set[str] = set()
    url = (
        f"https://web.archive.org/cdx/search/cdx?"
        f"url=*.{domain}&output=json&fl=original&collapse=urlkey&limit={limit}"
    )
    try:
        with httpx.Client(timeout=timeout, follow_redirects=True) as client:
            resp = client.get(url, headers={"User-Agent": "ARGUS/0.2"})
            if resp.status_code != 200:
                return subs
            data = resp.json()
            # 1ère ligne = header, on saute
            for row in data[1:] if len(data) > 1 else []:
                if not row:
                    continue
                full_url = row[0] if isinstance(row, list) else row
                # Extrait le host : "https://sub.domain.com/path?q=1" → "sub.domain.com"
                try:
                    host = full_url.split("//", 1)[-1].split("/", 1)[0].split(":")[0].lower()
                    if host == domain or host.endswith("." + domain):
                        subs.add(host)
                except Exception:
                    continue
    except Exception:
        pass
    return subs


# ─────────────────────────────────────────────────────────────
# Source 3 : DNS brute force (wordlist top 200)
# ─────────────────────────────────────────────────────────────

# Wordlist des 200 sous-domaines les plus communs, classés par fréquence d'apparition
# (compilé depuis SecLists/DNS-Jhaddix, Bug Bounty community).
COMMON_SUBDOMAINS = [
    "www", "mail", "webmail", "smtp", "pop", "imap", "ftp", "vpn", "remote", "portal",
    "admin", "blog", "news", "shop", "store", "forum", "wiki", "support", "help", "kb",
    "api", "api2", "api-v1", "api-v2", "rest", "graphql", "soap", "ws",
    "app", "apps", "m", "mobile", "mobi", "wap",
    "dev", "dev2", "test", "test2", "staging", "stage", "uat", "qa", "preprod", "preview",
    "beta", "alpha", "demo", "sandbox",
    "secure", "ssl", "auth", "sso", "oauth", "login", "signin", "register",
    "static", "cdn", "media", "img", "images", "files", "download", "downloads", "uploads",
    "video", "videos", "stream", "live",
    "ns", "ns1", "ns2", "ns3", "ns4", "dns", "dns1", "dns2", "mx", "mx1", "mx2",
    "intranet", "extranet", "internal", "private", "vpn1", "vpn2",
    "owa", "exchange", "outlook", "mail2", "mail3", "email", "newsletter",
    "calendar", "meet", "chat", "sms", "voice",
    "git", "gitlab", "github", "svn", "jira", "confluence", "wiki1", "redmine",
    "ci", "jenkins", "build", "deploy", "docker", "k8s",
    "search", "elastic", "kibana", "grafana", "prometheus", "monitor", "monitoring",
    "stats", "analytics", "metrics", "logs", "log",
    "crm", "cms", "erp", "hr", "rh", "finance", "comptabilite", "billing", "invoice",
    "sales", "marketing", "ads",
    "backup", "backups", "archive", "old", "legacy",
    "db", "mysql", "postgres", "mongo", "redis", "cache",
    "host", "server", "srv", "srv1", "srv2",
    "cpanel", "whm", "webdisk", "autodiscover", "autoconfig",
    "moodle", "elearning", "campus", "school", "etudiants", "students", "enseignants",
    "bibliotheque", "library", "docs", "documentation",
    "office", "365",
    "status", "dashboard", "panel", "control",
    "ws1", "ws2", "soap1",
    "fr", "en", "ar", "es", "pt", "de",
    "v1", "v2", "v3", "old-site", "new", "new-site",
    "client", "clients", "customers", "espace-client",
    "fournisseur", "fournisseurs", "partner", "partners",
    "site", "sites", "www1", "www2", "www3",
    "proxy", "gateway", "router", "firewall", "balance",
    "video1", "video2", "tv", "radio",
    "files1", "files2", "drive", "cloud", "s3", "storage",
    "qa1", "qa2", "test1", "test3", "rec", "recette",
    "training", "formation", "academy", "academie",
    "labs", "lab", "research", "rd", "dev1", "dev3",
    "blog1", "blog2", "blogs", "news1",
    "demo1", "demo2", "demos", "sandbox1",
    "edge", "front", "back", "core",
    "id", "identity", "accounts", "account",
    "pay", "payment", "payments", "gateway-pay",
    "ftp1", "ftp2", "sftp",
    "register", "registration", "subscribe",
    "alpha2", "alpha-staging", "test-api", "api-test", "api-dev", "api-staging", "api-uat",
    "api-prod", "api-old", "v0", "v4",
]


def _resolves(hostname: str, timeout: float = 2.0) -> bool:
    """Test rapide : ce hostname résout-il en DNS ?"""
    socket.setdefaulttimeout(timeout)
    try:
        socket.gethostbyname(hostname)
        return True
    except (socket.gaierror, socket.timeout, OSError):
        return False


def dns_bruteforce(
    domain: str,
    wordlist: list[str] | None = None,
    threads: int = 50,
) -> set[str]:
    """
    Test des sous-domaines communs en DNS (rapide, en parallèle).
    Retourne ceux qui résolvent (= existent vraiment).
    """
    candidates = wordlist or COMMON_SUBDOMAINS
    found: set[str] = set()

    def check(prefix: str) -> str | None:
        full = f"{prefix}.{domain}"
        return full if _resolves(full) else None

    with ThreadPoolExecutor(max_workers=threads) as pool:
        for result in pool.map(check, candidates):
            if result:
                found.add(result)
    return found


# ─────────────────────────────────────────────────────────────
# Source 4 : IA permutation (Claude analyse + génère)
# ─────────────────────────────────────────────────────────────

def ai_permutation(
    domain: str,
    known_subs: list[str],
    max_candidates: int = 80,
) -> set[str]:
    """
    Demande à Claude d'analyser les patterns dans les sous-domaines déjà trouvés
    et de générer des variantes probables.

    Ex : trouvé "api-staging.x.com, api-dev.x.com" → Claude génère "api-prod, api-qa,
         api-eu, api-v2", etc.

    DIFFÉRENTIATEUR UNIQUE : aucun concurrent ne fait ça.
    """
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key or api_key.startswith("sk-ant-..."):
        return set()
    if not known_subs:
        return set()

    from anthropic import Anthropic

    # On garde les 40 plus significatifs (= avec un préfixe avant le domaine racine)
    sample = sorted({s for s in known_subs if s.endswith("." + domain)})[:40]

    prompt = f"""Tu analyses des sous-domaines déjà trouvés sur {domain}.

Sous-domaines connus (échantillon) :
{chr(10).join(sample)}

Analyse les PATTERNS de nommage (préfixes, suffixes, séparateurs, conventions) et génère {max_candidates} sous-domaines PROBABLES qui n'apparaissent PAS dans la liste mais qui suivent les mêmes conventions.

Exemples de patterns à reconnaître :
- "api, api-v2" → suggère "api-v3, api-staging, api-prod, api-dev, api-internal"
- "mail, mail1" → suggère "mail2, mail3, mail-eu, mail-backup"
- "admin.x.com" → suggère "admin1, admin-old, admin-new, admin-dev, sso-admin"
- env-séparateurs (prod, dev, staging, uat) si tu vois 1 → essaie les autres

Rends UNIQUEMENT une liste de sous-domaines complets (un par ligne, sans tiret/numéro de liste, sans backticks, sans commentaire). N'inclus PAS de sous-domaines déjà dans la liste. Sois créatif mais reste cohérent avec les patterns observés."""

    try:
        client = Anthropic(api_key=api_key)
        response = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=2000,
            messages=[{"role": "user", "content": prompt}],
        )
        raw = response.content[0].text.strip()
    except Exception:
        return set()

    candidates: set[str] = set()
    for line in raw.splitlines():
        s = line.strip().lstrip("-•* 0123456789.").strip().lower()
        if not s:
            continue
        # Doit terminer par le domaine
        if s.endswith("." + domain) and s != domain:
            candidates.add(s)

    # Filtre : on valide en DNS pour ne garder que ceux qui existent vraiment
    if not candidates:
        return set()
    return dns_bruteforce(domain, wordlist=[c.replace("." + domain, "") for c in candidates], threads=50)


# ─────────────────────────────────────────────────────────────
# ORCHESTRATEUR
# ─────────────────────────────────────────────────────────────

def discover_all(
    domain: str,
    deep: bool = True,
    on_progress=None,
) -> dict:
    """
    Lance toutes les sources de découverte et merge les résultats.

    Args:
        domain    : domaine cible
        deep      : si True, active wayback + bruteforce + AI permutation (plus lent)
        on_progress: callback(source_name, count) appelé après chaque source

    Returns:
        {
          "subs": [liste mergée, dédoublonnée, triée],
          "by_source": {"crtsh": 234, "wayback": 89, "bruteforce": 47, "ai": 12}
        }
    """
    from app.scanner import run_subfinder  # import différé pour éviter cycle

    sources: dict[str, set[str]] = {}

    # Subfinder (toujours)
    try:
        subs = set(run_subfinder(domain))
        sources["subfinder"] = subs
    except Exception:
        sources["subfinder"] = set()
    if on_progress:
        on_progress("subfinder", len(sources["subfinder"]))

    # Crt.sh (toujours, gratuit et rapide)
    sources["crtsh"] = fetch_crtsh(domain)
    if on_progress:
        on_progress("crtsh", len(sources["crtsh"]))

    if deep:
        # Wayback (historique)
        sources["wayback"] = fetch_wayback(domain)
        if on_progress:
            on_progress("wayback", len(sources["wayback"]))

        # DNS brute force (top 200 communs)
        sources["bruteforce"] = dns_bruteforce(domain)
        if on_progress:
            on_progress("bruteforce", len(sources["bruteforce"]))

        # IA permutation (basée sur ce qu'on a déjà)
        union_so_far = set().union(*sources.values())
        sources["ai_permutation"] = ai_permutation(domain, list(union_so_far))
        if on_progress:
            on_progress("ai_permutation", len(sources["ai_permutation"]))

    # Merge final
    merged = sorted(set().union(*sources.values()))
    if domain not in merged:
        merged.insert(0, domain)

    return {
        "subs": merged,
        "by_source": {k: len(v) for k, v in sources.items()},
    }
