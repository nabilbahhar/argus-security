---
title: Comment savoir si votre WordPress a des vulnérabilités exploitables
slug: wordpress-vulnerable-detection-cve
description: WordPress équipe 40% du web et c'est la cible n°1 des attaquants. Voici comment détecter si votre site est vulnérable avant qu'un hacker ne le fasse.
keywords: wordpress vulnérable, détecter wordpress hacké, sécurité wordpress, plugin wordpress vulnérabilité, CVE wordpress
date: 2026-05-19
reading_time: 7 min
category: WordPress
---

Vous avez un site WordPress. Vous le maintenez à jour quand vous y pensez. Vous installez quelques plugins quand vous en avez besoin. Et un jour, votre site est piraté — sans que vous ayez fait quoi que ce soit de mal.

C'est l'histoire classique de **30 à 40% des compromissions WordPress** : un plugin obsolète, une version core en retard, ou un thème vulnérable. Voici comment vérifier votre exposition.

## Pourquoi WordPress est la cible n°1

WordPress propulse plus de **40% des sites du web mondial**. Pour un attaquant qui veut compromettre un maximum de cibles avec un minimum d'effort, c'est l'écosystème parfait :

- **Le core WordPress** est généralement bien maintenu, mais les versions anciennes traînent partout
- **Les plugins** sont écrits par des milliers de développeurs de qualité variable, avec **des CVE découvertes chaque semaine**
- **Les thèmes** premium contiennent souvent du code obsolète (sliders, page builders, etc.)
- **Les configurations par défaut** sont faibles (admin/admin reste la combinaison la plus testée)

Les attaquants utilisent des **scanners automatiques** (wpscan, nuclei avec templates WordPress) qui parcourent Internet 24/7 à la recherche de versions vulnérables connues. Ils n'ont pas besoin de vous cibler. Vous êtes juste dans le lot.

## Les 5 indicateurs de vulnérabilité

### 1. Version du core WordPress

Vérifiez quelle version vous utilisez. Si vous êtes en dessous de la **version 6.4**, vous êtes exposé à des CVE patchées dans les versions plus récentes.

**Comment vérifier facilement** : consultez `https://votresite.com/readme.html` (souvent accessible publiquement). Sinon, dans l'admin → Tableau de bord → Mises à jour.

**Si version ancienne** : mettez à jour **maintenant**. La mise à jour core est généralement sans risque (sauvegarde + 1 click).

### 2. Plugins obsolètes ou non maintenus

Allez dans Extensions → Toutes les extensions, et regardez :
- Combien de plugins n'ont **pas été mis à jour depuis plus de 6 mois** côté WordPress.org ?
- Combien de plugins sont marqués **"non testé avec votre version de WordPress"** ?
- Combien de plugins **n'ont plus de support actif** (auteur disparu) ?

> **Statistique** : plus de 50% des compromissions WordPress passent par un plugin vulnérable.

**Action** :
- Supprimer (vraiment supprimer, pas juste désactiver) tout plugin non utilisé
- Mettre à jour ceux qui restent
- Remplacer ceux qui ne sont plus maintenus par une alternative active

### 3. Thèmes en plus du thème actif

Beaucoup de sites WordPress installent plusieurs thèmes "pour essayer" et n'en suppriment qu'un. **Chaque thème non utilisé reste exploitable** : si une CVE est découverte dans le thème "Twenty Sixteen" et que vous l'avez encore installé (même inactif), vous êtes vulnérable.

**Action** : supprimez tous les thèmes que vous n'utilisez pas. Gardez uniquement le thème actif + le dernier thème par défaut de WordPress (utile pour debug).

### 4. Configurations dangereuses

Plusieurs configurations courantes facilitent les attaques :

- **`/wp-admin` accessible depuis n'importe quelle IP** : permet le brute-force
- **XML-RPC activé** sans nécessité : permet le brute-force amplifié (`xmlrpc.php?for=`)
- **Énumération des utilisateurs** via `?author=1`, `?author=2` : révèle vos logins
- **REST API `/wp-json/wp/v2/users`** : liste publique de vos utilisateurs

**Actions concrètes** :
- Limiter `/wp-admin` par IP allowlist (via `.htaccess` ou plugin)
- Désactiver XML-RPC si non utilisé
- Désactiver l'énumération des utilisateurs (plugin Stop User Enumeration)
- Restreindre la REST API users aux utilisateurs authentifiés

### 5. Comptes admin faibles

- **Compte "admin" existe** : c'est le login que tous les attaquants testent en premier
- **Mots de passe simples** : `entreprise123`, `boss2024`, le nom de l'entreprise
- **Pas de 2FA** : un mot de passe compromis = compte ouvert

**Actions** :
1. Renommer "admin" en quelque chose d'unique (créer un nouveau compte admin, supprimer l'ancien)
2. Mots de passe **uniques de 16+ caractères** (Bitwarden/1Password)
3. **2FA obligatoire** via plugin (Wordfence, Two Factor, miniOrange)

## Les scénarios d'attaque concrets

### Scénario 1 — Plugin RCE

Un plugin de gestion de fichiers a une CVE qui permet l'upload de fichiers arbitraires. L'attaquant uploade un webshell PHP. Quelques secondes plus tard, il a un accès complet au serveur.

**Détection** : votre scanner détecte la version du plugin → vous voyez "Plugin X version Y.Z avec CVE-2024-XXXX (EPSS 87%)".

### Scénario 2 — Brute-force /wp-admin

Pas de rate-limit, pas de 2FA. Un bot teste 100 000 mots de passe en 24h. Un seul réussit. L'attaquant injecte un compte admin caché et exfiltre votre base.

**Détection** : pic de tentatives de connexion dans les logs.

### Scénario 3 — Theme vulnérable XSS

Un thème ancien permet l'injection JavaScript via un champ commentaire. L'attaquant injecte un keylogger qui vole les sessions admin.

**Détection** : audit du code des thèmes inutilisés.

### Scénario 4 — XML-RPC amplification

L'attaquant utilise `xmlrpc.php?for=` pour multiplier ses tentatives de connexion par 1000 dans une seule requête. Brute-force massif avec un seul handshake.

**Détection** : trafic anormal sur `/xmlrpc.php`.

## Comment auditer en 5 minutes

1. **Scanner externe** (sans installation) : [lancez un scan ARGUS](/) sur votre domaine. Il détecte la version WordPress, les plugins identifiables, les versions techno (PHP, jQuery, etc.) et les compare aux CVE connues.

2. **Audit interne** :
   - Connectez-vous à `/wp-admin`
   - Mettez à jour TOUT (core + plugins + thèmes)
   - Supprimez les plugins/thèmes non utilisés
   - Activez 2FA via Wordfence ou similaire
   - Désactivez XML-RPC dans les paramètres

## Pour aller plus loin

Une fois ces bases en place :
- Installez un **WAF** (Cloudflare gratuit ou WordFence Pro)
- Configurez des **sauvegardes automatiques** (UpdraftPlus, BackupBuddy)
- Activez **HTTPS partout** (Let's Encrypt gratuit)
- Monitoring d'intégrité de fichiers (Sucuri, Wordfence)

[ARGUS Security](/) scanne votre WordPress et tous vos autres actifs web en 60 secondes, sans plugin à installer. Vous voyez immédiatement les versions exposées, les sous-domaines avec d'autres WordPress oubliés, et les vulnérabilités exploitables.

**La cybersécurité d'un WordPress n'est pas un mystère. C'est de la discipline appliquée à 4-5 réflexes.**
