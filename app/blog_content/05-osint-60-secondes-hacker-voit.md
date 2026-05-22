---
title: OSINT en 60 secondes — ce qu'un hacker voit déjà de votre entreprise
slug: osint-hacker-voit-entreprise
description: La reconnaissance OSINT est la première étape de toute attaque ciblée. Voici ce qu'un attaquant trouve sur vous en 60 secondes, sans rien faire d'illégal.
keywords: OSINT entreprise, reconnaissance hacker, scan domaine OSINT, informations publiques entreprise, footprinting
date: 2026-05-18
reading_time: 6 min
category: Reconnaissance
---

OSINT = Open Source Intelligence. Toute l'information **publique** qu'un attaquant collecte sur vous **avant** de lancer une attaque. Cette phase est invisible (aucune trace dans vos logs), légale, gratuite, et en 60 secondes elle révèle déjà 90% de ce qu'il a besoin de savoir.

Voici ce qu'un attaquant trouve sur votre entreprise quand il vous cible.

## Les sources OSINT principales

### 1. Le DNS public

Votre nom de domaine est associé à plein d'informations publiques :
- **Tous vos sous-domaines** révélés via les requêtes DNS, les bases de certificats SSL (Certificate Transparency logs), les archives web (Wayback Machine)
- **Vos serveurs email** (MX records) — révèlent souvent votre fournisseur (Google Workspace, Microsoft 365, ProtonMail, OVH)
- **Vos IP** publiques associées (records A et AAAA)
- **Vos plages d'adresses IP** si vous avez votre propre AS (BGP)

> Un attaquant ne brute-force jamais vos DNS. Il consulte des bases déjà constituées (Censys, Shodan, crt.sh) où votre infrastructure est répertoriée depuis des années.

### 2. Les certificats SSL publics

Chaque certificat SSL émis pour votre domaine est publié dans des logs **publics** (Certificate Transparency) consultables par tous. Cela inclut :
- Tous vos sous-domaines, **même internes** (`admin.entreprise.com`, `vpn.entreprise.com`)
- Les dates d'émission et d'expiration
- Le nom de votre autorité de certification

Conséquence : impossible de cacher un sous-domaine derrière un certificat HTTPS. La création même du certificat est publique.

### 3. Les archives web (Wayback Machine)

Le site `archive.org` conserve des **snapshots historiques** de vos pages web. Un attaquant trouve :
- Les anciennes versions de votre site (avec des liens vers des pages qui n'existent plus mais qui ont gardé leurs fichiers serveur)
- Des **commentaires HTML** que vos développeurs ont laissés
- Des **chemins de fichiers** anciens encore accessibles
- Des **informations de stack** révélées dans les en-têtes HTTP historiques

### 4. Les moteurs de recherche spécialisés

- **Shodan** : indexe tous les services exposés sur Internet (ports, bannières, versions). Tape simplement votre nom de domaine et tu vois tout ce qui est ouvert.
- **Censys** : pareil mais avec d'autres scanners
- **Google dorks** : `site:entreprise.com filetype:pdf` révèle vos PDF publics. `site:entreprise.com inurl:admin` cherche les pages admin.

### 5. Les fuites de données passées

- **HaveIBeenPwned** : si un employé s'est inscrit sur LinkedIn, Dropbox, Adobe, MySpace, et que ces services ont été piratés, son email + mot de passe est dans des bases publiques achetables pour 10€.
- **Pastebin** : combien de credentials, clés API, configurations sensibles sont publiées par erreur par des développeurs ?

### 6. Les réseaux sociaux

- **LinkedIn** : qui sont vos employés ? Avec quels intitulés (admin systèmes, RSSI, développeur senior) ? Quels outils utilisent-ils (vu dans les compétences) ?
- **GitHub** : vos développeurs ont-ils des dépôts publics révélant votre stack ? Des configurations leakées ?
- **Twitter/X** : annonces tech, plaintes sur les outils, screenshots de produits internes

## Ce qu'un attaquant déduit en 60 secondes

À partir de ces sources publiques uniquement, un attaquant établit en moins d'une minute :

### Profil technique de votre infrastructure
- Hébergeur (AWS, OVH, Cloudflare, etc.)
- Stack web (WordPress 6.0 + nginx 1.18 + PHP 8.1 = chaque version a des CVE associées)
- Service email (Google Workspace, Microsoft 365)
- Outils internes exposés (Jenkins, Gitlab, Confluence si vous en avez et qu'ils sont publics)

### Carte de votre surface d'attaque
- Tous vos sous-domaines actifs
- Tous vos sous-domaines abandonnés (les "trésors" pour les attaquants)
- Vos environnements de test/dev s'ils sont exposés
- Vos APIs publiques

### Profil humain
- Les noms et fonctions de vos employés clés
- Leurs emails (déduits du pattern : prenom.nom@entreprise.com)
- Leurs comptes sur des services tiers
- Leurs mots de passe potentiellement leakés dans des breaches passés

### Plan d'attaque
À partir de tout ça, l'attaquant construit son plan :
- **Phishing ciblé** sur les employés clés avec un prétexte crédible (sait que vous utilisez Google Workspace → page de phishing imitant Google)
- **Brute-force** sur les sous-domaines admin trouvés
- **Exploit CVE** sur les versions techno identifiées
- **Spray attack** avec les mots de passe leakés sur tous vos comptes employés

Tout ça **sans avoir touché à votre infrastructure**. Aucune trace, aucune alerte.

## Comment se protéger

### Réduire votre empreinte OSINT

- **Sous-domaines internes** : utiliser un nommage non-révélateur. Pas `prod-payments.entreprise.com` mais `srv-a47.entreprise.com`. Ou utiliser un sous-domaine séparé non lié au principal.
- **Wildcard SSL** : utiliser des certificats wildcard `*.entreprise.com` plutôt que des certs individuels pour chaque sous-domaine. Cache le détail de votre infrastructure.
- **Headers serveur** : retirer `X-Powered-By`, `Server` version, `X-AspNet-Version`. Configurations standard mais souvent oubliées.
- **Pages publiques** : auditer ce qui est indexable. Bloquer les pages admin via `robots.txt` ET via authentification.

### Réduire votre empreinte humaine

- **Sensibiliser** les employés au sur-partage LinkedIn (descriptions de poste trop précises sur la stack interne)
- **Auditer** les dépôts GitHub publics — utiliser `truffleHog` pour détecter des secrets
- **Forcer le 2FA** partout pour neutraliser les credentials leakés
- **Renouveler** les mots de passe employés trouvés sur HaveIBeenPwned

### Faire votre propre OSINT régulièrement

La meilleure défense, c'est de **faire la même reconnaissance qu'un attaquant** sur votre propre entreprise tous les mois.

[ARGUS Security](/) automatise cette phase : en 60 secondes, vous obtenez la même vision qu'un attaquant aurait de vous. Vous voyez vos sous-domaines exposés, vos technos identifiables, vos configurations email faibles, et les sous-domaines à risque (admin, dev, old, etc.).

L'idée n'est pas de devenir paranoïaque. C'est de savoir **ce que voit déjà l'extérieur** pour pouvoir le contrôler.

**Ce que vous ne voyez pas, vous ne pouvez pas le protéger.**
