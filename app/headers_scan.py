"""
headers_scan.py — Audit des headers HTTP et cookies des actifs vivants

Même contrat que surface_risk / tech_insights : analyze_headers() + score_impact().
Un finding par type de problème (pas par actif), pour garder un rapport lisible
même avec plusieurs centaines d'actifs.

Les actifs sans headers collectés (scans antérieurs à cet audit) sont ignorés :
une donnée absente n'est jamais interprétée comme un header manquant.
"""

from __future__ import annotations
import re

SESSION_COOKIE_RE = re.compile(r"sess|auth|token|jwt|login|logged|^sid$|connect\.sid", re.I)
VERSION_RE = re.compile(r"\d+\.\d+")
UNSAFE_CHARS_RE = re.compile(r"[^\w./ :+-]")
DISCLOSURE_HEADERS = ("x_powered_by", "x_aspnet_version", "x_aspnetmvc_version", "x_generator")
SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}
MAX_HOSTS_LISTED = 5

ISSUES = {
    "cookie_flags": {
        "severity": "high",
        "title": "Cookies de session mal protégés",
        "label_short": "Flags Secure ou HttpOnly absents",
        "explanation": "Des cookies de session sont émis sans les protections Secure ou HttpOnly.",
        "scenario": (
            "Un attaquant qui trouve une faille XSS lit le cookie de session en JavaScript et "
            "prend le contrôle du compte connecté. Sans Secure, le cookie peut aussi circuler "
            "en clair et être capté sur un réseau Wi-Fi public."
        ),
        "recommendation": (
            "Ajouter Secure, HttpOnly et SameSite=Lax à tous les cookies de session, dans la "
            "configuration de l'application ou du framework."
        ),
    },
    "cors": {
        "severity": "high",
        "title": "Politique CORS permissive",
        "label_short": "Origine * avec credentials",
        "explanation": "Le serveur autorise toutes les origines tout en acceptant les requêtes authentifiées.",
        "scenario": (
            "Cette configuration signale une politique cross-origin mal maîtrisée. Si le serveur "
            "reflète aussi l'origine appelante, un site piégé peut lire les données d'un "
            "utilisateur connecté à son insu."
        ),
        "recommendation": (
            "Remplacer * par une liste explicite d'origines de confiance et n'activer "
            "Allow-Credentials que pour celles-ci."
        ),
    },
    "version_leak": {
        "severity": "medium",
        "title": "Versions logicielles divulguées",
        "label_short": "Headers trop bavards",
        "explanation": "Les réponses HTTP révèlent le logiciel exact et sa version.",
        "scenario": (
            "Un attaquant n'a plus besoin de deviner : il croise la version annoncée avec les "
            "failles connues et cible directement celles qui s'appliquent, sans déclencher "
            "d'alerte."
        ),
        "recommendation": (
            "Masquer les versions : ServerTokens Prod (Apache), server_tokens off (nginx), "
            "expose_php = Off (PHP), et retirer X-Powered-By au niveau du reverse proxy."
        ),
    },
    "hsts": {
        "severity": "medium",
        "title": "HSTS absent",
        "label_short": "HTTPS non imposé par le navigateur",
        "explanation": "Le navigateur n'a pas pour consigne de refuser les connexions non chiffrées.",
        "scenario": (
            "Sur un réseau Wi-Fi public, un attaquant intercepte la toute première requête HTTP "
            "de la victime et la maintient en clair : identifiants et cookies passent sous ses yeux."
        ),
        "recommendation": (
            "Ajouter Strict-Transport-Security: max-age=31536000; includeSubDomains sur toutes "
            "les réponses HTTPS."
        ),
    },
    "csp": {
        "severity": "medium",
        "title": "Content-Security-Policy absente",
        "label_short": "Aucune limite sur les scripts chargés",
        "explanation": "Aucune politique ne limite les sources de scripts autorisées dans les pages.",
        "scenario": (
            "La moindre faille d'injection devient une exécution de script complète : vol de "
            "session, faux formulaire de connexion ou redirection vers une page de phishing."
        ),
        "recommendation": (
            "Déployer une Content-Security-Policy, d'abord en mode Report-Only pour repérer les "
            "scripts légitimes, puis en mode bloquant."
        ),
    },
    "clickjacking": {
        "severity": "medium",
        "title": "Protection anti-clickjacking absente",
        "label_short": "Pages intégrables dans une iframe",
        "explanation": "Ni X-Frame-Options ni frame-ancestors n'empêchent l'intégration des pages sur un site tiers.",
        "scenario": (
            "Un attaquant affiche votre page dans une iframe invisible sur son site : la victime "
            "croit cliquer sur un bouton anodin et valide en réalité une action sur son compte."
        ),
        "recommendation": (
            "Ajouter X-Frame-Options: DENY ou, mieux, la directive CSP frame-ancestors 'self'."
        ),
    },
    "nosniff": {
        "severity": "low",
        "title": "X-Content-Type-Options absent",
        "label_short": "Détection de type MIME active",
        "explanation": "Le navigateur peut réinterpréter le type des fichiers servis.",
        "scenario": (
            "Un fichier déposé via un formulaire d'upload, présenté comme une image, peut être "
            "exécuté comme script par le navigateur."
        ),
        "recommendation": "Ajouter X-Content-Type-Options: nosniff sur toutes les réponses.",
    },
    "referrer": {
        "severity": "low",
        "title": "Referrer-Policy absente",
        "label_short": "URL complètes transmises aux sites tiers",
        "explanation": "Les URL visitées peuvent être transmises aux sites externes appelés par vos pages.",
        "scenario": (
            "Les URL contenant un jeton de réinitialisation ou un identifiant fuitent vers les "
            "scripts et sites tiers appelés depuis la page."
        ),
        "recommendation": "Ajouter Referrer-Policy: strict-origin-when-cross-origin.",
    },
}


def _text(value) -> str:
    if isinstance(value, list):
        return " ".join(str(v) for v in value)
    return str(value or "")


def _clean(value: str) -> str:
    # Valeurs envoyées par le serveur scanné : elles finissent dans le rapport et l'export
    return UNSAFE_CHARS_RE.sub("", value)[:40]


def _hostname(url: str) -> str:
    return url.split("//", 1)[-1].split("/", 1)[0]


def _weak_session_cookies(raw, is_https: bool) -> list[str]:
    cookies = raw if isinstance(raw, list) else [raw] if raw else []
    weak = []
    for cookie in cookies:
        name, _, attrs = str(cookie).partition(";")
        name = name.split("=", 1)[0].strip()
        attrs = attrs.lower()
        if not SESSION_COOKIE_RE.search(name):
            continue
        if "httponly" not in attrs or (is_https and "secure" not in attrs):
            weak.append(_clean(name))
    return weak


def _audit_asset(url: str, headers: dict) -> dict[str, list[str]]:
    """Retourne {issue_id: [détails]} pour un actif."""
    is_https = url.startswith("https")
    csp = _text(headers.get("content_security_policy"))
    found: dict[str, list[str]] = {}

    if is_https and not headers.get("strict_transport_security"):
        found["hsts"] = []
    if not csp:
        found["csp"] = []
    if not headers.get("x_frame_options") and "frame-ancestors" not in csp.lower():
        found["clickjacking"] = []
    if not headers.get("x_content_type_options"):
        found["nosniff"] = []
    if not headers.get("referrer_policy"):
        found["referrer"] = []

    server = _text(headers.get("server"))
    leaks = [server] if VERSION_RE.search(server) else []
    leaks += [_text(headers[h]) for h in DISCLOSURE_HEADERS if headers.get(h)]
    if leaks:
        found["version_leak"] = [_clean(v) for v in leaks]

    weak_cookies = _weak_session_cookies(headers.get("set_cookie"), is_https)
    if weak_cookies:
        found["cookie_flags"] = weak_cookies

    origin = _text(headers.get("access_control_allow_origin")).strip()
    credentials = _text(headers.get("access_control_allow_credentials")).strip().lower()
    if origin == "*" and credentials == "true":
        found["cors"] = []

    return found


def _describe_hosts(hosts: list[str]) -> str:
    listed = ", ".join(hosts[:MAX_HOSTS_LISTED])
    rest = len(hosts) - MAX_HOSTS_LISTED
    return f"{listed} et {rest} autre(s)" if rest > 0 else listed


def analyze_headers(assets: list[dict]) -> dict:
    """
    Args:
        assets: dicts avec "url", "status_code" et "probe" (sortie de la sonde HTTP).

    Returns:
        {"findings": [...], "stats": {"high": n, "medium": n, "low": n}}
    """
    affected: dict[str, list[str]] = {}
    details: dict[str, list[str]] = {}

    for asset in assets:
        headers = (asset.get("probe") or {}).get("headers")
        status = asset.get("status_code") or 0
        url = asset.get("url") or ""
        if headers is None or not 200 <= status < 400:
            continue
        host = _hostname(url)
        for issue, issue_details in _audit_asset(url, headers).items():
            hosts = affected.setdefault(issue, [])
            if host not in hosts:
                hosts.append(host)
            known = details.setdefault(issue, [])
            known.extend(d for d in issue_details if d not in known)

    findings = []
    for issue in sorted(affected, key=lambda i: SEVERITY_ORDER[ISSUES[i]["severity"]]):
        spec = ISSUES[issue]
        hosts = affected[issue]
        observed = f" Observé : {', '.join(details[issue][:5])}." if details.get(issue) else ""
        findings.append({
            "issue": issue,
            "title": spec["title"],
            "severity": spec["severity"],
            "label_short": spec["label_short"],
            "explanation": f"{spec['explanation']}{observed} Concerne {len(hosts)} actif(s) : {_describe_hosts(hosts)}.",
            "scenario": spec["scenario"],
            "recommendation": spec["recommendation"],
        })

    stats = {"high": 0, "medium": 0, "low": 0}
    for finding in findings:
        stats[finding["severity"]] += 1
    return {"findings": findings, "stats": stats}


def score_impact(stats: dict) -> tuple[int, str]:
    high, medium, low = stats.get("high", 0), stats.get("medium", 0), stats.get("low", 0)
    total = high + medium + low
    if not total:
        return 0, ""
    delta = -min(15, 5 * high + 3 * medium + low)
    return delta, f"{total} protection(s) HTTP manquante(s) ou mal configurée(s)."
