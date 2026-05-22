"""
surface_risk.py — Analyse de patterns d'exposition à risque dans les sous-domaines.

Détecte les sous-domaines dont le nom suggère un usage sensible (admin, backoffice,
ancien, dev, etc.) et génère des findings avec scénarios d'exploitation concrets.

Philosophie : on ne banalise jamais. Un sous-domaine "old.exemple.com" exposé
publiquement, même s'il renvoie un 200 anodin, est une porte d'entrée potentielle
pour un attaquant qui cherche les actifs oubliés.
"""

from typing import Iterable


# ── Catalogue de patterns par niveau de risque ────────────────────────────

# CRITIQUE : interfaces d'administration / panneaux de contrôle
PATTERNS_ADMIN = [
    "admin", "administrator", "administration",
    "bo", "backoffice", "back-office", "back_office",
    "dashboard", "console", "panel", "control", "manage", "management",
    "root", "su", "sudo", "privileged",
    "internal", "private", "intranet",
    "portal-admin", "manager",
    "phpmyadmin", "pma", "adminer",
    "kibana", "grafana", "prometheus", "elasticsearch",
    "jenkins", "gitlab-admin", "jira-admin",
]

# ÉLEVÉ : actifs oubliés / non maintenus
PATTERNS_LEGACY = [
    "old", "ancien", "ancienne", "legacy", "deprecated", "archive", "archived",
    "v1", "v2", "v3", "v4", "v5",
    "backup", "bkp", "bak", "save", "dump", "snapshot",
    "tmp", "temp", "temporary",
]

# ÉLEVÉ : environnements de dev/test exposés
PATTERNS_DEV = [
    "dev", "develop", "development", "develop-",
    "staging", "stage", "stg",
    "test", "testing", "tests", "qa", "qua",
    "uat", "preprod", "preproduction", "pre-prod", "pre-production",
    "demo", "sandbox", "lab", "labs", "poc",
    "beta", "alpha",
]

# MOYEN : services techniques sensibles exposés au public
PATTERNS_SERVICE_SENSIBLE = [
    "ftp", "sftp", "files", "fileserver",
    "smtp", "pop", "imap",
    "vpn", "remote", "rdp", "ssh-web",
    "ci", "cd", "build", "deploy",
    "monitor", "monitoring", "metric", "metrics", "status",
    "logs", "log-server",
    "registry", "docker-registry",
    "git", "svn",
    "confluence", "wiki-internal", "sonarqube",
    "redis", "mongo", "mysql", "postgres", "couchdb",
]

# Pour info : actifs API exposés (à mentionner sans pénaliser fort)
PATTERNS_API = [
    "api", "apis", "graphql", "graph", "rest", "rpc",
    "ws", "websocket", "stream",
    "webhook", "webhooks",
]


SEVERITY_ADMIN = "critical"
SEVERITY_LEGACY = "high"
SEVERITY_DEV = "high"
SEVERITY_SERVICE = "medium"
SEVERITY_API = "info"


def _first_label(hostname: str, root_domain: str) -> str:
    """
    Extrait le label le plus à gauche du hostname, hors www.
    'old.pam.ma' avec root='pam.ma' → 'old'
    'bo.dev.pam.ma' → 'bo'
    'www.pam.ma' → '' (filtré)
    """
    if not hostname:
        return ""
    h = hostname.lower().strip().rstrip(".")
    root = (root_domain or "").lower().strip().rstrip(".")
    # Enlève le root si présent
    if root and h.endswith("." + root):
        sub = h[: -(len(root) + 1)]
    elif h == root:
        return ""
    else:
        sub = h
    if not sub or sub == "www":
        return ""
    # Premier label
    return sub.split(".")[0]


def _match_patterns(label: str, patterns: list[str]) -> str | None:
    """Retourne le pattern matché ou None. Match exact ou commence par."""
    if not label:
        return None
    for p in patterns:
        if label == p:
            return p
        # Préfixe + caractère séparateur (admin-old, dev1, etc.)
        if label.startswith(p) and len(label) > len(p):
            next_char = label[len(p)]
            if not next_char.isalpha():  # admin1, admin-old → match. administrator → pas match exact
                return p
    return None


def analyze_surface(hostnames: Iterable[str], root_domain: str) -> dict:
    """
    Analyse les sous-domaines découverts pour identifier les surfaces à risque.

    Returns:
        {
            "findings": [
                {
                    "host": "bo.pam.ma",
                    "category": "admin",        # admin | legacy | dev | service | api
                    "severity": "critical",     # critical | high | medium | info
                    "pattern": "bo",
                    "label_short": "Interface d'administration probable",
                    "explanation": "...",
                    "scenario": "...",
                    "recommendation": "...",
                },
                ...
            ],
            "stats": {
                "critical": 2,
                "high": 5,
                "medium": 1,
                "info": 3,
            }
        }
    """
    findings = []
    stats = {"critical": 0, "high": 0, "medium": 0, "info": 0}

    seen = set()
    for h in hostnames:
        if not h or h in seen:
            continue
        seen.add(h)
        label = _first_label(h, root_domain)
        if not label:
            continue

        # On vérifie dans l'ordre de criticité (admin d'abord, puis legacy, etc.)
        for patterns, category, severity, finding_builder in [
            (PATTERNS_ADMIN, "admin", SEVERITY_ADMIN, _build_admin_finding),
            (PATTERNS_LEGACY, "legacy", SEVERITY_LEGACY, _build_legacy_finding),
            (PATTERNS_DEV, "dev", SEVERITY_DEV, _build_dev_finding),
            (PATTERNS_SERVICE_SENSIBLE, "service", SEVERITY_SERVICE, _build_service_finding),
            (PATTERNS_API, "api", SEVERITY_API, _build_api_finding),
        ]:
            matched = _match_patterns(label, patterns)
            if matched:
                f = finding_builder(h, matched)
                f["category"] = category
                f["severity"] = severity
                f["pattern"] = matched
                findings.append(f)
                stats[severity] += 1
                break  # Un seul match par hostname (le plus critique)

    return {"findings": findings, "stats": stats}


def _build_admin_finding(host: str, matched: str) -> dict:
    return {
        "host": host,
        "label_short": "Interface d'administration probable",
        "explanation": (
            f"Le sous-domaine « {host} » contient le motif « {matched} », typique "
            f"des panneaux d'administration et back-offices. Sa simple exposition "
            f"publique le rend cible n°1 du brute-force d'identifiants, des scans "
            f"automatisés et des CVE de panels (Joomla admin, WordPress wp-admin, "
            f"Bitrix, etc.)."
        ),
        "scenario": (
            f"Un attaquant qui découvre {host} va d'abord tester les comptes par "
            f"défaut (admin/admin, root/root, admin/password123…), puis exécuter "
            f"un dictionnaire de mots de passe usuels. En moins d'une minute, des "
            f"outils gratuits scannent ce type d'URL en testant des milliers de "
            f"combinaisons. Si une seule fonctionne — vous perdez le contrôle "
            f"du back-office."
        ),
        "recommendation": (
            f"Restreindre l'accès à {host} par VPN, IP allowlist ou authentification "
            f"forte (2FA + IP restriction). Si l'usage public est inévitable : "
            f"WAF + rate-limit agressif + monitoring temps réel des tentatives."
        ),
    }


def _build_legacy_finding(host: str, matched: str) -> dict:
    return {
        "host": host,
        "label_short": "Actif ancien / potentiellement abandonné",
        "explanation": (
            f"Le sous-domaine « {host} » suit un nommage typique des versions "
            f"héritées, archivées ou de sauvegarde (motif « {matched} »). Ce genre "
            f"d'actif est rarement maintenu : versions de logiciel obsolètes, "
            f"correctifs de sécurité non appliqués, comptes oubliés."
        ),
        "scenario": (
            f"Un attaquant qui repère {host} sait qu'il s'agit probablement d'un "
            f"site qui ne reçoit plus de mises à jour. Il va y déployer ses CVE "
            f"de masse (RCE WordPress 5.x, injection SQL Drupal 7, Apache "
            f"path-traversal CVE-2021-41773…). Comme personne ne regarde les logs "
            f"de cet actif, il peut s'installer et utiliser le serveur comme point "
            f"d'entrée pour pivoter vers le reste de votre infrastructure."
        ),
        "recommendation": (
            f"Décider rapidement : soit {host} est désactivé (redirection 410 Gone), "
            f"soit il est remis à jour comme un actif de production (patches, "
            f"monitoring, dans le périmètre de scan continu). L'oubli est le "
            f"pire des choix."
        ),
    }


def _build_dev_finding(host: str, matched: str) -> dict:
    return {
        "host": host,
        "label_short": "Environnement de développement/test exposé",
        "explanation": (
            f"Le sous-domaine « {host} » suggère un environnement non-production "
            f"(motif « {matched} »). Ces environnements contiennent souvent des "
            f"données de test issues de la prod, des credentials hardcodés en "
            f"debug, des messages d'erreur verbeux qui révèlent l'architecture, "
            f"et des frameworks en mode développeur."
        ),
        "scenario": (
            f"Un attaquant qui tombe sur {host} y trouvera typiquement : "
            f"messages d'erreur Django/Symfony exposant le code source, "
            f"endpoints de debug (/admin/debug, /_debug, /actuator) actifs, "
            f"identifiants en clair dans des commentaires HTML, jetons d'API "
            f"dans des fichiers .env oubliés. Il peut aussi essayer les comptes "
            f"de test « test/test », « demo/demo » très souvent valides."
        ),
        "recommendation": (
            f"Mettre {host} derrière une authentification HTTP basique ou un "
            f"VPN. Aucun environnement non-production ne devrait jamais être "
            f"directement accessible depuis Internet."
        ),
    }


def _build_service_finding(host: str, matched: str) -> dict:
    return {
        "host": host,
        "label_short": "Service technique exposé",
        "explanation": (
            f"Le sous-domaine « {host} » correspond à un service interne typique "
            f"(motif « {matched} »). Beaucoup de ces services (CI, monitoring, "
            f"registry, bases NoSQL) sont conçus pour un réseau privé, pas pour "
            f"être directement exposés à Internet."
        ),
        "scenario": (
            f"Un attaquant qui découvre {host} cherchera les CVE connues du "
            f"produit, les configurations par défaut (Jenkins sans auth, Grafana "
            f"admin/admin, ElasticSearch sans firewall), et les fuites d'info via "
            f"les endpoints publics non protégés (build logs, métriques exposant "
            f"les versions de toute la stack…)."
        ),
        "recommendation": (
            f"Restreindre {host} aux IP autorisées ou le passer derrière un VPN. "
            f"Vérifier qu'aucune interface d'admin n'est accessible sans "
            f"authentification forte."
        ),
    }


def _build_api_finding(host: str, matched: str) -> dict:
    return {
        "host": host,
        "label_short": "API publique détectée",
        "explanation": (
            f"Le sous-domaine « {host} » expose une API ({matched}). Les API "
            f"publiques sont normales, mais elles élargissent la surface d'attaque : "
            f"endpoints non documentés, contrôles d'authentification incohérents, "
            f"injection via paramètres, fuites de données par énumération."
        ),
        "scenario": (
            f"Un attaquant énumère les endpoints de {host} (avec ffuf, kiterunner) "
            f"pour trouver des routes oubliées, teste l'IDOR (changer un ID dans "
            f"l'URL pour accéder à des données d'autres utilisateurs), et abuse "
            f"des authentifications faibles (JWT mal signés, tokens prédictibles)."
        ),
        "recommendation": (
            f"Documenter exhaustivement {host} (OpenAPI), implémenter un rate-limit "
            f"par token, auditer les permissions sur chaque endpoint, et logger "
            f"toutes les requêtes anormales."
        ),
    }


def score_impact(stats: dict) -> tuple[int, str]:
    """
    Convertit les stats de findings surface en delta de score.

    Returns: (delta, reason_text)
    """
    delta = 0
    parts = []

    crit = stats.get("critical", 0)
    high = stats.get("high", 0)
    med = stats.get("medium", 0)

    if crit > 0:
        # -10 par interface admin, plafonné à -25
        d = -min(25, 10 * crit)
        delta += d
        parts.append(f"{crit} interface(s) d'administration exposée(s)")

    if high > 0:
        # -5 par actif ancien/dev, plafonné à -20
        d = -min(20, 5 * high)
        delta += d
        parts.append(f"{high} actif(s) hérité(s) ou de développement exposé(s)")

    if med > 0:
        # -3 par service technique exposé, plafonné à -10
        d = -min(10, 3 * med)
        delta += d
        parts.append(f"{med} service(s) technique(s) exposé(s) publiquement")

    if not parts:
        return 0, ""

    reason = ". ".join(parts) + "."
    return delta, reason
