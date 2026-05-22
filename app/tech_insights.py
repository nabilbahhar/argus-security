"""
tech_insights.py — Enrichissement des technos détectées par httpx/Wappalyzer.

Pour chaque techno trouvée sur un actif (ex: "WordPress:6.4", "PHP:8.1.0",
"nginx:1.18", "jQuery:1.12"), on génère un insight :
  - Niveau de risque (info / low / medium / high / critical)
  - Statut de la version (EOL, ancien, à jour, inconnu)
  - Scénario d'exploitation typique
  - Recommandation

Philosophie : on ne banalise jamais. Détecter PHP 8.1 ou WordPress 6.0
permet déjà à un attaquant de cibler les CVE de cette version. On le dit.
"""

from typing import Iterable
import re


# Versions "fin de vie" connues — manuellement maintenues, sans appel réseau
# (on évite d'aller consulter endoflife.date en live pour rester rapide)

EOL_DATABASE = {
    # PHP — https://www.php.net/supported-versions.php
    "php": {
        "eol_versions": ["5.", "7.", "8.0", "8.1"],  # 8.1 EOL 2024-11
        "current_safe": "8.2+",
    },
    # WordPress core — https://wordpress.org/about/security/
    "wordpress": {
        "eol_versions": ["3.", "4.", "5."],  # tout < 6.x est risqué
        "current_safe": "6.4+",
    },
    # nginx — https://nginx.org/en/CHANGES
    "nginx": {
        "eol_versions": ["0.", "1.0", "1.1", "1.2", "1.3", "1.4", "1.5", "1.6",
                         "1.7", "1.8", "1.9", "1.10", "1.11", "1.12", "1.13",
                         "1.14", "1.15", "1.16", "1.17", "1.18", "1.19"],
        "current_safe": "1.24+",
    },
    # Apache httpd
    "apache": {
        "eol_versions": ["1.", "2.0", "2.2", "2.4.0", "2.4.1", "2.4.2", "2.4.3",
                         "2.4.4", "2.4.5", "2.4.6", "2.4.49"],
        "current_safe": "2.4.58+",
    },
    # jQuery — https://jquery.com/
    "jquery": {
        "eol_versions": ["1.", "2."],  # 1.x et 2.x = XSS connues
        "current_safe": "3.7+",
    },
    # Node.js
    "node": {
        "eol_versions": ["0.", "4.", "6.", "8.", "10.", "12.", "14.", "16."],
        "current_safe": "20+",
    },
    "nodejs": {  # alias
        "eol_versions": ["0.", "4.", "6.", "8.", "10.", "12.", "14.", "16."],
        "current_safe": "20+",
    },
    # Python (rare en frontend mais bon)
    "python": {
        "eol_versions": ["2.", "3.0", "3.1", "3.2", "3.3", "3.4", "3.5", "3.6", "3.7"],
        "current_safe": "3.11+",
    },
}


# Pour chaque techno (ou famille) : scénario générique d'exploitation
# Sert quand on n'a pas de version précise mais qu'on veut quand même éduquer.

INSIGHTS_TEMPLATES = {
    "wordpress": {
        "label_short": "WordPress détecté",
        "explanation": "WordPress propulse plus de 40% du web. C'est aussi la "
                       "cible n°1 des attaques automatisées : plugins vulnérables, "
                       "thèmes non maintenus, mots de passe d'admin faibles.",
        "scenario": "Un attaquant lance des scanners automatiques (wpscan, nuclei) "
                    "qui testent en quelques secondes : plugins vulnérables connus, "
                    "comptes admin par défaut, énumération d'utilisateurs via "
                    "/wp-json/wp/v2/users, brute-force /wp-login.php. Plus de 30% "
                    "des compromissions WordPress passent par un plugin obsolète.",
        "recommendation": "Activer la double-authentification sur /wp-admin, "
                          "limiter les tentatives de connexion (plugin Limit Login "
                          "Attempts), supprimer les plugins non utilisés, mettre à "
                          "jour TOUS les plugins et thèmes au moins toutes les 2 semaines.",
        "severity_baseline": "medium",
    },
    "drupal": {
        "label_short": "Drupal détecté",
        "explanation": "Drupal a connu plusieurs CVE critiques type \"Drupalgeddon\" "
                       "qui permettent une exécution de code à distance non "
                       "authentifiée. Une version pas à jour = compromission "
                       "quasi-garantie en quelques heures.",
        "scenario": "Un attaquant identifie la version exacte de Drupal via "
                    "/CHANGELOG.txt ou les fichiers JS, puis lance les exploits "
                    "publics correspondants (Drupalgeddon 1/2/3). En quelques "
                    "minutes, il peut prendre le contrôle complet du serveur.",
        "recommendation": "Tenir Drupal core ET tous les modules à jour. Suivre "
                          "les alertes security.drupal.org. Cacher /CHANGELOG.txt "
                          "et /UPGRADE.txt par règle serveur.",
        "severity_baseline": "high",
    },
    "joomla": {
        "label_short": "Joomla détecté",
        "explanation": "Joomla a plusieurs CVE critiques chaque année, dont "
                       "régulièrement des injections SQL non-authentifiées. "
                       "L'écosystème d'extensions multiplie la surface.",
        "scenario": "Scan automatique pour identifier la version exacte (via "
                    "/administrator/manifests/files/joomla.xml), puis exploit ciblé.",
        "recommendation": "Mettre à jour Joomla + toutes les extensions. "
                          "Restreindre /administrator par IP allowlist.",
        "severity_baseline": "medium",
    },
    "php": {
        "label_short": "Version PHP exposée",
        "explanation": "La version exacte de PHP est révélée dans les headers "
                       "(X-Powered-By, Server). Un attaquant utilise cette info "
                       "pour cibler les CVE de cette version précise — chaque "
                       "version PHP a des CVE de fin de vie connues.",
        "scenario": "L'attaquant consulte exploit-db avec votre version PHP et "
                    "trouve les RCE, déni de service, contournements d'authentification "
                    "publiquement documentés. Si la version est en EOL, aucun patch "
                    "n'arrivera plus.",
        "recommendation": "Masquer X-Powered-By (expose_php=Off dans php.ini). "
                          "Migrer vers une version PHP supportée.",
        "severity_baseline": "low",
    },
    "nginx": {
        "label_short": "Version nginx exposée",
        "explanation": "Les headers HTTP exposent la version exacte de nginx. "
                       "Chaque version a des CVE associées (path traversal, "
                       "request smuggling, header injection).",
        "scenario": "L'attaquant identifie la version, consulte nginx.org/CHANGES "
                    "pour les vulnérabilités fixées, et lance les exploits.",
        "recommendation": "Désactiver server_tokens (server_tokens off; dans la "
                          "config nginx) pour masquer la version. Maintenir nginx à "
                          "jour mensuellement.",
        "severity_baseline": "info",
    },
    "apache": {
        "label_short": "Apache HTTP Server détecté",
        "explanation": "Apache a connu plusieurs CVE critiques récentes "
                       "(CVE-2021-41773 path traversal, CVE-2021-42013, etc.). "
                       "Une version pas à jour est immédiatement exploitable.",
        "scenario": "L'attaquant identifie la version (ServerTokens), trouve les "
                    "CVE publiques, et lance les exploits. CVE-2021-41773 permet "
                    "de lire n'importe quel fichier du serveur en une requête.",
        "recommendation": "ServerTokens Prod + ServerSignature Off. Maintenir "
                          "Apache à jour. Vérifier la config mod_rewrite + Alias.",
        "severity_baseline": "low",
    },
    "jquery": {
        "label_short": "jQuery détecté",
        "explanation": "jQuery 1.x et 2.x ont des vulnérabilités XSS connues. "
                       "Même jQuery 3.x ancien peut être vulnérable à la pollution "
                       "de prototype et au DOM-based XSS.",
        "scenario": "Si vous chargez du contenu utilisateur via jQuery (selectors, "
                    "html(), append()), un attaquant peut injecter du JavaScript "
                    "qui s'exécutera chez tous vos visiteurs (vol de cookies, "
                    "phishing transparent).",
        "recommendation": "Migrer vers jQuery 3.7+ ou s'en passer (vanilla JS). "
                          "Toujours échapper le contenu utilisateur avant injection DOM.",
        "severity_baseline": "info",
    },
    "openssl": {
        "label_short": "OpenSSL détecté en bannière",
        "explanation": "OpenSSL est souvent ciblé (Heartbleed, FREAK, POODLE…). "
                       "Si la version est ancienne, des MITM ou des fuites mémoire "
                       "deviennent possibles.",
        "scenario": "Un attaquant teste votre handshake TLS et identifie les "
                    "extensions/protocoles supportés. Si la version est vulnérable "
                    "à Heartbleed, il peut extraire des clés privées et sessions.",
        "recommendation": "Migrer vers OpenSSL 3.0+. Désactiver TLS 1.0/1.1.",
        "severity_baseline": "info",
    },
    "phpmyadmin": {
        "label_short": "phpMyAdmin EXPOSÉ — RISQUE TRÈS ÉLEVÉ",
        "explanation": "phpMyAdmin est une interface web pour MySQL/MariaDB. "
                       "Son exposition publique est une faute de configuration "
                       "majeure : c'est la porte directe vers votre base de données.",
        "scenario": "Un attaquant teste les comptes par défaut (root/root, "
                    "root/password, admin/admin), puis lance un brute-force massif. "
                    "Une seule réussite et toute votre base de données est lisible "
                    "ET modifiable. Ransomware en perspective.",
        "recommendation": "RETIRER IMMÉDIATEMENT l'accès public à phpMyAdmin. "
                          "Restreindre par IP allowlist et placer derrière un VPN.",
        "severity_baseline": "critical",
    },
    "wpbakery": {
        "label_short": "WPBakery Page Builder détecté",
        "explanation": "WPBakery (anciennement Visual Composer) est un plugin "
                       "WordPress très ciblé : XSS persistant, RCE via upload, "
                       "contournements d'authentification.",
        "scenario": "Un attaquant cherche les versions de WPBakery vulnérables "
                    "(via fingerprinting), puis exploite les XSS ou contourne "
                    "l'authentification pour injecter du code dans les pages.",
        "recommendation": "Maintenir WPBakery à jour, désactiver les modules "
                          "non utilisés, restreindre les uploads.",
        "severity_baseline": "medium",
    },
    "yoast": {
        "label_short": "Yoast SEO détecté",
        "explanation": "Yoast SEO est le plugin WordPress le plus installé. "
                       "Plusieurs CVE par an (XSS, SQL injection). Une version "
                       "non patchée est rapidement exploitée.",
        "scenario": "Les attaquants automatisent la détection de versions Yoast "
                    "vulnérables. Une faille XSS dans Yoast peut être utilisée "
                    "pour injecter du code dans la console d'admin WP.",
        "recommendation": "Maintenir Yoast à jour. Surveiller les bulletins "
                          "wpvulndb.com.",
        "severity_baseline": "low",
    },
    "iis": {
        "label_short": "Microsoft IIS détecté",
        "explanation": "IIS expose souvent sa version dans X-Powered-By et "
                       "X-AspNet-Version. Selon la version Windows Server, "
                       "des CVE critiques sont connues (HTTP.sys, ASP.NET).",
        "scenario": "Identification version IIS + Windows Server → recherche "
                    "CVE Microsoft → exploit.",
        "recommendation": "Désactiver X-Powered-By et X-AspNet-Version. "
                          "Maintenir Windows Server patché (KB mensuels).",
        "severity_baseline": "info",
    },
}


def _split_name_version(tech_str: str) -> tuple[str, str]:
    """
    'WordPress:6.4'     → ('wordpress', '6.4')
    'PHP/8.1.0'         → ('php', '8.1.0')
    'jQuery 3.6'        → ('jquery', '3.6')
    'nginx'             → ('nginx', '')
    """
    if not tech_str:
        return "", ""
    s = tech_str.strip()
    # Patterns courants : "Name:Version", "Name/Version", "Name Version"
    m = re.match(r"^([A-Za-z][\w \-\.]*?)[\s:/]+([\d][\d\.\w\-]*)$", s)
    if m:
        return m.group(1).strip().lower(), m.group(2).strip()
    return s.lower(), ""


def _is_eol(name: str, version: str) -> bool:
    """Renvoie True si la version est connue comme EOL pour cette techno."""
    if not version:
        return False
    entry = EOL_DATABASE.get(name)
    if not entry:
        return False
    for prefix in entry["eol_versions"]:
        if version.startswith(prefix):
            # Évite les false matches type "1.2" matché par "1." quand on a "10.x"
            # On vérifie que le prochain char après le préfixe est un séparateur OU fin
            rest = version[len(prefix):]
            if not rest or rest[0] in (".", "-", " "):
                return True
            # Cas "1.2" matché par "1." : OK
            if prefix.endswith(".") and rest[0].isdigit():
                return True
    return False


def _bump_severity(baseline: str, eol: bool) -> str:
    """Augmente la sévérité d'un cran si EOL."""
    if not eol:
        return baseline
    order = ["info", "low", "medium", "high", "critical"]
    try:
        i = order.index(baseline)
        return order[min(len(order) - 1, i + 1)]
    except ValueError:
        return baseline


def _normalize_name(tech_name_raw: str) -> str | None:
    """
    Renvoie une clé canonique pour matcher INSIGHTS_TEMPLATES.
    'WordPress' → 'wordpress', 'WP Bakery' → 'wpbakery', etc.
    """
    if not tech_name_raw:
        return None
    n = tech_name_raw.lower().strip()
    n_clean = re.sub(r"[^a-z0-9]", "", n)  # Enlève espaces, slashes, etc.

    # Aliases / matchings approximatifs
    if "wordpress" in n_clean or n_clean == "wp":
        return "wordpress"
    if "drupal" in n_clean:
        return "drupal"
    if "joomla" in n_clean:
        return "joomla"
    if n_clean == "php" or n_clean.startswith("php"):
        return "php"
    if n_clean == "nginx":
        return "nginx"
    if "apache" in n_clean and "log4j" not in n_clean:
        return "apache"
    if "jquery" in n_clean:
        return "jquery"
    if "openssl" in n_clean:
        return "openssl"
    if "phpmyadmin" in n_clean or n_clean == "pma":
        return "phpmyadmin"
    if "wpbakery" in n_clean or "visualcomposer" in n_clean:
        return "wpbakery"
    if "yoast" in n_clean:
        return "yoast"
    if n_clean == "iis":
        return "iis"
    if "nodejs" in n_clean or n_clean == "node":
        return "node"
    if n_clean == "python":
        return "python"
    return None


def analyze_techs(techs: Iterable[str]) -> dict:
    """
    Analyse une liste de chaînes techno (issues du champ Asset.tech httpx).

    Returns:
        {
            "findings": [
                {
                    "tech": "WordPress",
                    "version": "6.4",
                    "is_eol": False,
                    "severity": "medium",
                    "label_short": "WordPress détecté",
                    "explanation": "...",
                    "scenario": "...",
                    "recommendation": "...",
                },
                ...
            ],
            "stats": {"critical": N, "high": N, "medium": N, "low": N, "info": N},
        }
    """
    findings_by_tech = {}  # déduplication par techno
    stats = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    for raw in techs or []:
        if not raw:
            continue
        name_raw, version = _split_name_version(str(raw))
        canonical = _normalize_name(name_raw)
        if not canonical or canonical in findings_by_tech:
            continue
        template = INSIGHTS_TEMPLATES.get(canonical)
        if not template:
            continue
        eol = _is_eol(canonical, version)
        severity = _bump_severity(template["severity_baseline"], eol)
        finding = {
            "tech": name_raw.title() if name_raw else canonical.title(),
            "version": version,
            "is_eol": eol,
            "severity": severity,
            "label_short": template["label_short"],
            "explanation": template["explanation"],
            "scenario": template["scenario"],
            "recommendation": template["recommendation"],
        }
        if eol:
            finding["explanation"] = (
                f"⚠️ Version {version} en fin de vie (EOL) — plus aucun patch de sécurité ne sera publié. "
                + finding["explanation"]
            )
        findings_by_tech[canonical] = finding

    findings = list(findings_by_tech.values())
    for f in findings:
        stats[f["severity"]] = stats.get(f["severity"], 0) + 1

    return {"findings": findings, "stats": stats}


def score_impact(stats: dict) -> tuple[int, str]:
    """
    Convertit les stats de findings techno en delta de score.
    """
    delta = 0
    parts = []

    crit = stats.get("critical", 0)
    high = stats.get("high", 0)
    med = stats.get("medium", 0)

    if crit > 0:
        d = -min(20, 10 * crit)
        delta += d
        parts.append(f"{crit} techno(s) critique(s) (phpMyAdmin, etc.)")

    if high > 0:
        d = -min(12, 4 * high)
        delta += d
        parts.append(f"{high} techno(s) en fin de vie ou très ciblée(s)")

    if med > 0:
        d = -min(6, 2 * med)
        delta += d
        parts.append(f"{med} techno(s) à risque modéré (versions exposées)")

    if not parts:
        return 0, ""

    reason = ". ".join(parts) + "."
    return delta, reason
