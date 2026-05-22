---
title: Les 5 sous-domaines à surveiller en priorité (admin, dev, old…)
slug: sous-domaines-risque-admin-dev-old
description: bo, admin, old, staging, test — ces sous-domaines sont les premières cibles d'un attaquant. Voici pourquoi et comment vous protéger.
keywords: sous-domaines exposés, admin exposé, sous-domaine dev, vérifier sous-domaines, shadow IT
date: 2026-05-21
reading_time: 6 min
category: Reconnaissance
---

Un attaquant qui cible votre entreprise commence rarement par votre site principal. Il commence par chercher **les sous-domaines oubliés**. Voici les 5 patterns qu'il teste systématiquement, et ce que vous devez faire si vous en trouvez chez vous.

## Pourquoi les sous-domaines sont la première porte d'entrée

Votre site principal (`www.entreprise.com`) est probablement maintenu, mis à jour, protégé par un WAF. C'est la **vitrine**.

Mais derrière, il y a souvent :
- Un ancien site (`old.entreprise.com`) qui ne reçoit plus de patchs depuis 2 ans
- Une interface d'admin (`bo.entreprise.com`) accessible depuis Internet
- Un environnement de dev (`dev.entreprise.com`) avec des credentials hardcodés
- Des services techniques (`jenkins.entreprise.com`, `grafana.entreprise.com`) configurés pour un réseau privé mais exposés au public par erreur

Ces sous-domaines sont des **portes de service ouvertes** pendant que la porte principale est blindée. Un attaquant le sait. Il commence par énumérer tous vos sous-domaines avec des outils comme `subfinder`, `amass`, ou via les bases de certificats SSL publics (crt.sh).

## Les 5 patterns à risque

### 1. Patterns d'administration (CRITIQUE)

**Mots-clés à chercher** : `admin`, `administrator`, `bo`, `backoffice`, `panel`, `dashboard`, `console`, `manage`, `phpmyadmin`, `pma`, `kibana`, `grafana`, `jenkins`.

**Pourquoi c'est critique** :
Ces sous-domaines exposent généralement une interface de connexion. Un attaquant lance un brute-force automatique avec les comptes par défaut (admin/admin, root/root) ou un dictionnaire de mots de passe usuels. **Plus de 30% des compromissions WordPress passent par /wp-admin exposé.**

**Action concrète** :
1. Restreindre par **IP allowlist** (seul votre VPN ou vos bureaux peuvent y accéder)
2. Activer le **2FA obligatoire** sur tous les comptes
3. Mettre derrière un **VPN d'entreprise** (Tailscale, WireGuard, OpenVPN)
4. Si exposition publique inévitable : **WAF + rate-limit agressif + monitoring temps réel**

### 2. Patterns "ancien" / "legacy" (ÉLEVÉ)

**Mots-clés à chercher** : `old`, `ancien`, `legacy`, `deprecated`, `archive`, `archived`, `v1`, `v2`, `backup`, `bkp`, `tmp`, `temp`.

**Pourquoi c'est risqué** :
Ces sites sont rarement maintenus. Plus de mises à jour. Mots de passe oubliés. Versions de WordPress, Drupal, PHP en fin de vie. C'est un terrain de chasse parfait : un attaquant y déploie ses exploits de masse (Drupalgeddon, WordPress plugin RCE, Apache path-traversal) et **personne ne regarde les logs**.

Une fois compromis, le serveur sert de **point d'appui** pour pivoter vers le reste de votre infrastructure interne.

**Action concrète** :
Trancher rapidement entre deux options :
- **Désactiver** : remplacer la page par un `410 Gone` et fermer le port 80/443
- **Maintenir** : remettre dans le périmètre de scan continu + patches + monitoring, comme un actif de production

Le pire choix est l'oubli.

### 3. Environnements de développement/test (ÉLEVÉ)

**Mots-clés à chercher** : `dev`, `develop`, `staging`, `stage`, `stg`, `test`, `qa`, `uat`, `preprod`, `demo`, `sandbox`, `beta`, `alpha`.

**Pourquoi c'est risqué** :
Ces environnements contiennent souvent :
- Des **données de test issues de la production** (clients réels, parfois en clair)
- Des **credentials hardcodés** en mode debug
- Des **messages d'erreur verbeux** qui révèlent le code source, les versions exactes, les chemins de fichiers
- Des **endpoints de debug** actifs (`/debug`, `/_debug`, `/actuator`, `/health`, `/metrics`)
- Des **comptes de test faibles** (test/test, demo/demo, admin/123456)

**Action concrète** :
Aucun environnement non-production ne devrait être **directement accessible depuis Internet**. Mettez tout derrière :
- Authentification HTTP basique
- VPN d'entreprise
- IP allowlist

### 4. Services techniques exposés (MOYEN)

**Mots-clés à chercher** : `jenkins`, `gitlab`, `jira`, `confluence`, `sonarqube`, `kibana`, `grafana`, `prometheus`, `nexus`, `registry`, `docker-registry`, `redis`, `mongo`, `mysql`, `postgres`, `couchdb`, `elasticsearch`.

**Pourquoi c'est risqué** :
Ces outils sont conçus pour un réseau **privé**. Exposés publiquement, ils ont souvent des configurations par défaut faibles, des CVE non patchées, et fuient de l'information critique (versions de toute votre stack, métriques internes, snippets de code).

**Cas réel** : Jenkins exposé sans authentification = exécution de scripts Groovy arbitraires = compromission du serveur en quelques minutes.

**Action concrète** :
Auditer chaque service technique exposé. Pour chaque :
- A-t-il **vraiment besoin** d'être public ?
- Si oui, est-il **à jour** et avec une **auth forte** ?
- Sinon : derrière un VPN, point.

### 5. APIs et endpoints fonctionnels (FAIBLE-MOYEN)

**Mots-clés à chercher** : `api`, `api-v2`, `graphql`, `rest`, `webhook`, `stream`, `ws`.

**Pourquoi c'est à surveiller** :
Les APIs publiques sont normales (sinon votre app web ne marche pas). Mais elles **élargissent considérablement la surface d'attaque** :
- Endpoints **non documentés** trouvés par énumération (ffuf, kiterunner)
- **IDOR** : changer un ID dans l'URL pour accéder aux données d'autres utilisateurs
- **Authentifications faibles** : JWT mal signés, tokens prédictibles
- **Rate-limit absent** : permet le data scraping massif

**Action concrète** :
- Documenter exhaustivement (OpenAPI / Swagger)
- Rate-limit par token
- Audit permissions sur chaque endpoint
- Logger toutes les requêtes anormales

## Comment trouver vos sous-domaines à risque (en 60 secondes)

Au lieu de faire l'inventaire à la main (impossible si vous avez plus de 50 sous-domaines), utilisez un outil de reconnaissance qui combine plusieurs sources :
- Bases publiques de certificats SSL (Certificate Transparency)
- Archives web (Wayback Machine)
- DNS bruteforce avec wordlists
- Moteurs OSINT

[ARGUS Security](/) fait ça en moins d'une minute et vous flag automatiquement les sous-domaines à risque avec un scénario d'exploitation concret pour chacun.

**Conseil final** : faites cet exercice 1 fois par mois. Les sous-domaines apparaissent et disparaissent vite (déploiements, tests, migrations) et c'est la meilleure source de mauvaises surprises.
