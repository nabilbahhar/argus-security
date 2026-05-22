---
title: Comment scanner son site web pour détecter les vulnérabilités (sans être expert)
slug: scanner-securite-site-web
description: Méthode pratique pour auditer la sécurité de votre site web — outils, étapes, comment interpréter les résultats. Sans installer quoi que ce soit.
keywords: scanner sécurité site web, audit cybersécurité site, vulnérabilités web, scan vulnérabilité gratuit
date: 2026-05-22
reading_time: 7 min
category: Audit
---

Vous avez un site web. Vous savez qu'il y a probablement des trous de sécurité. Mais vous n'êtes pas développeur ou pas RSSI. Comment savoir si quelqu'un peut vous pirater ?

Bonne nouvelle : vous pouvez auditer la sécurité de votre site **sans installer un seul outil**, en moins de 5 minutes, et comprendre les résultats sans bac+5 en cyber. Voici la méthode complète.

## Pourquoi scanner son site (avant les hackers)

Les attaquants ne ciblent pas que les grandes banques. Ils scannent Internet 24/7 avec des outils automatiques. Si votre site a une faille connue, ils la trouvent en quelques heures — et ils n'ont pas besoin de vous connaître personnellement.

Les conséquences d'une faille non corrigée :
- **Site défacé** ou redirigé vers du contenu pirate
- **Données clients fuitées** (RGPD : amende possible)
- **SEO sanctionné** par Google quand votre site sert de relais à des malwares
- **Spam envoyé** depuis votre serveur → blacklist email
- **Ransomware** sur les fichiers du serveur

Un scan régulier permet de **trouver ces failles avant qu'un attaquant ne les exploite**.

## Les 4 niveaux de scan possibles

### Niveau 1 — Le scan passif (le minimum vital)

Ce type de scan ne touche **pas** votre site. Il interroge uniquement des sources publiques (DNS, certificats SSL, archives web, moteurs de recherche). Aucun risque légal, aucune trace dans vos logs, gratuit.

Il identifie principalement :
- Tous les sous-domaines existants
- La configuration email (SPF, DKIM, DMARC)
- L'état des certificats SSL/TLS
- Les technologies utilisées (WordPress, PHP, etc.)

C'est ce que fait [ARGUS Security](/) en mode gratuit. **Recommandé pour démarrer.**

### Niveau 2 — Le scan de vulnérabilités web

Plus intrusif : il envoie des requêtes pour tester des vulnérabilités connues (CVE). Il peut détecter des injections SQL, des XSS, des configurations faibles.

**Attention** : ce type de scan génère du trafic visible dans vos logs et **doit être autorisé** par le propriétaire du domaine. Sur votre propre site, aucun souci.

### Niveau 3 — Le pentest manuel

Un humain expert teste votre site selon une méthodologie (OWASP, OSSTMM). C'est ce qui détecte les vulnérabilités logiques complexes (escalade de privilèges, race conditions, mauvaise gestion des sessions).

Coût : entre 3000 et 30000€ selon la profondeur. Réservé aux entreprises avec un vrai enjeu.

### Niveau 4 — Le bug bounty

Vous publiez un programme qui paie les chercheurs en sécurité qui trouvent des bugs. Très efficace mais nécessite une infrastructure (HackerOne, YesWeHack) et un budget.

## Comment lire les résultats d'un scan

Vous lancez un scan. Vous obtenez 200 lignes de findings. Comment savoir ce qui est urgent ?

### Le score global

Un bon outil vous donne **une note globale** (A à F par exemple). C'est le résumé en un coup d'œil :
- **A** : posture exemplaire, rien d'urgent
- **B** : OK, quelques points à durcir
- **C** : moyen, action recommandée sous 30 jours
- **D** : mauvais, action urgente
- **F** : critique, on parle d'aujourd'hui

### Les niveaux de sévérité par finding

Chaque vulnérabilité est classée :
- **Critique (P1)** : exploitation immédiate possible, données compromettables
- **Élevée (P2)** : exploitation faisable, risque significatif
- **Moyenne (P3)** : exploitation conditionnelle
- **Basse / Info** : à corriger mais pas urgent

### Les indicateurs qui changent tout

Au-delà de la sévérité brute, deux indicateurs disent **si cette faille est utilisée en pratique** :

- **EPSS** (Exploit Prediction Scoring System) : probabilité que cette faille soit exploitée dans les 30 jours. Au-dessus de 50% = à corriger maintenant.
- **KEV** (Known Exploited Vulnerabilities) : catalogue CISA des CVE déjà utilisées par des attaquants. Si votre faille est dans la liste KEV, vous êtes une cible.

> Une CVE avec EPSS 95% + KEV active doit être patchée dans la semaine, peu importe le reste de votre roadmap.

## Les 5 trucs à corriger en priorité (issus de 90% des scans)

D'après les patterns observés sur des milliers d'audits, voici ce qui ressort le plus souvent — et qui se corrige vite.

### 1. Sous-domaines abandonnés exposés

`old.exemple.com`, `bo.exemple.com`, `dev.exemple.com` traînent souvent en ligne avec des versions obsolètes de WordPress, des configurations de test, des comptes admin par défaut. Ce sont **les premières cibles** des attaquants.

**Action** : faire l'inventaire, désactiver ce qui ne sert plus, isoler le reste derrière un VPN.

### 2. Configuration email manquante

Pas de DMARC = n'importe qui peut envoyer des emails au nom de votre domaine. C'est ainsi que démarrent 90% des attaques de phishing ciblées.

**Action** : publier `v=DMARC1; p=none; rua=mailto:postmaster@votredomaine.com` pour commencer en monitoring, puis durcir en `p=quarantine` après 30 jours.

### 3. Versions logicielles obsolètes

PHP 7.x, WordPress 5.x, jQuery 1.x — autant de versions sans patch de sécurité depuis des années. Chaque CVE publique est exploitable.

**Action** : auditer les versions, planifier les mises à jour.

### 4. Interfaces d'administration exposées

`/wp-admin`, `/admin`, `/phpmyadmin` accessibles publiquement = brute-force massif inévitable.

**Action** : restreindre par IP allowlist, activer le 2FA, ou passer derrière un VPN.

### 5. Certificats SSL expirés ou faibles

Un certificat expiré bloque les navigateurs. Un protocole TLS 1.0 obsolète permet le MITM.

**Action** : Let's Encrypt + renouvellement automatique + désactiver TLS < 1.2.

## Conclusion : commencez par un scan passif

La cybersécurité d'un site web n'est pas un projet à 100 000€. C'est une discipline régulière. La première étape — **scanner sa propre surface d'attaque** — prend 60 secondes et coûte zéro.

ARGUS Security vous le permet sans installation et sans compte. [Testez votre domaine maintenant](/), vous serez surpris de ce qu'on y trouve.
