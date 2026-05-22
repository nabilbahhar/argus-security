---
title: 10 signes que votre site web a été compromis (et que faire)
slug: signes-site-web-pirate-compromis
description: Votre site est-il compromis sans que vous le sachiez ? Voici les 10 indicateurs concrets à surveiller, et les actions immédiates si vous en repérez un.
keywords: site web piraté, savoir si site compromis, signe site hacké, détecter compromission, malware site web
date: 2026-05-15
reading_time: 7 min
category: Incident response
---

Un site web compromis ne devient pas toujours évidemment "pirate". Beaucoup de compromissions sont **silencieuses** : un attaquant a accès à votre serveur depuis des mois, vole tranquillement vos données ou utilise votre site pour héberger du contenu pirate, sans laisser de signe visible.

Voici les 10 signaux qui doivent vous alerter — et la marche à suivre si vous en détectez un.

## 1. Trafic anormal vers des pages que vous ne connaissez pas

**Comment le détecter** : dans Google Analytics ou Plausible, vous voyez du trafic vers `/wp-content/uploads/file.php`, `/admin.bak/`, ou des URL bizarres que vous n'avez jamais créées.

**Pourquoi c'est inquiétant** : un attaquant a uploadé un **webshell** ou une page de phishing sur votre serveur et la fait pointer vers son trafic.

**Action immédiate** :
- Identifier le fichier suspect
- Mettre le site en maintenance le temps de l'investigation
- Comparer le système de fichiers avec une sauvegarde propre récente

## 2. Vos emails finissent soudainement en spam

**Symptôme** : vos clients vous disent "je n'ai pas reçu votre email", alors qu'il marchait avant.

**Causes possibles** :
- Votre serveur a été utilisé pour envoyer du spam → IP blacklistée
- Votre domaine a été usurpé en masse → réputation détruite

**Action** :
- Vérifier votre IP sur [MXToolbox blacklist](https://mxtoolbox.com/blacklists.aspx)
- Vérifier votre score Sender Reputation sur Talos Intelligence
- Auditer les logs SMTP pour détecter les envois suspects

## 3. Google Search Console vous notifie

**Comment le voir** : Google envoie un email "Problème de sécurité détecté sur votre site" et bannière rouge dans Search Console.

**Types** :
- **Pages piratées** : Google a détecté des pages injectées sur votre site
- **Logiciel malveillant** : votre site sert du malware aux visiteurs
- **Hameçonnage** : votre site est utilisé pour phishing
- **Téléchargements dangereux** : fichiers infectés en download

**Action** :
- Nettoyer immédiatement (voir étapes ci-dessous)
- Demander une révision via Search Console après nettoyage
- Si Google a marqué votre site "non sûr" dans Chrome, vous perdez **80% de votre trafic**

## 4. Nouveaux comptes administrateurs apparaissent

**Comment le détecter** : audit régulier de la liste des admins dans WordPress, Drupal, ou votre CMS.

**Pattern classique** : un compte "admin1", "wpadmin", "support", ou un nom random qui n'a rien à faire là.

**Action** :
- Supprimer immédiatement le compte
- Changer **tous** les mots de passe admin
- Activer 2FA si pas fait
- Auditer les logs pour comprendre comment il a été créé

## 5. Modifications de fichiers récentes que vous n'avez pas faites

**Comment le détecter** :
- En SSH : `find /var/www -mtime -7 -type f` (liste les fichiers modifiés ces 7 derniers jours)
- Plugin d'intégrité (Wordfence, Sucuri, BlogVault)

**Patterns suspects** :
- Fichiers PHP dans `/wp-content/uploads/` (normalement images uniquement)
- Modifications dans `wp-config.php`, `.htaccess`, `functions.php`
- Nouveaux fichiers avec des noms random (`a8jd72.php`, `cache.php`)

**Action** :
- **Ne pas supprimer immédiatement** — copier d'abord pour analyse
- Restaurer une sauvegarde antérieure à la modification
- Auditer les permissions de fichiers

## 6. Redirections vers des sites suspects

**Symptôme** : un utilisateur arrive sur votre site et est immédiatement redirigé vers `pharmacie-en-ligne-xxx.com` ou un site de phishing.

**Variantes courantes** :
- Redirection **uniquement** depuis mobile (l'attaquant épargne les desktops pour rester sous le radar)
- Redirection **uniquement** depuis Google (vous, qui tapez directement l'URL, ne voyez rien)
- Redirection après une certaine heure / un certain pays

**Où ça se cache** :
- `.htaccess` (souvent au sein de règles `RewriteRule`)
- `wp-config.php`
- En base de données dans les options ou les commentaires
- En JS injecté dans le footer

**Action** :
- Audit complet `.htaccess` + thème actif + `wp-config.php`
- Recherche en DB : `SELECT * FROM wp_options WHERE option_value LIKE '%http%'`
- Nettoyage manuel ou via un outil comme Wordfence Scanner

## 7. Pages de phishing hébergées sur votre site

**Comment le détecter** : 
- Vous recevez un email "merci pour votre inscription à PayPal/Amazon" alors que vous ne vous êtes pas inscrit
- En cherchant `site:votresite.com` sur Google, vous voyez des pages bizarres
- Une amitié vous dit "j'ai cliqué sur un lien de phishing qui pointait vers ton site"

**Action** :
- Trouver et supprimer les fichiers
- Notifier votre hébergeur (qui peut vous aider à nettoyer)
- Soumettre à Google Safe Browsing pour retirer la flag si bannie

## 8. Pics de bande passante ou consommation CPU inexplicables

**Comment le détecter** : votre hébergeur vous alerte ou vos métriques montrent un pic.

**Causes possibles** :
- Cryptominer installé qui mine de la cryptomonnaie pour l'attaquant
- Bot DDoS lancé depuis votre serveur
- Serveur utilisé comme proxy malveillant

**Action** :
- Auditer les processus en cours (`ps aux | grep -v "^\[" | sort -rk 3 | head`)
- Tuer les processus suspects
- Auditer les cron jobs (`crontab -l` + `/etc/cron.d/`)

## 9. Comptes utilisateurs piratés en chaîne

**Symptôme** : plusieurs utilisateurs de votre service vous signalent que leur compte est compromis, alors qu'ils ont des mots de passe différents.

**Causes** :
- Votre base de données a été volée (les attaquants reverse-engineer les mots de passe)
- Votre service authentifie via un système compromis
- Un keylogger est installé sur votre site (script JS injecté)

**Action** :
- **Forcer reset de tous les mots de passe**
- Audit du code frontend (scripts JS suspects)
- Audit de la DB pour identifier la fuite
- **Notifier les utilisateurs** (et la CNIL si données personnelles dans l'UE)

## 10. Présence sur des dumps de données

**Comment le détecter** :
- Surveillance via HaveIBeenPwned (gratuit)
- Mention de votre domaine sur Pastebin, RaidForums, BreachForums

**Si confirmé** : c'est probablement le résultat d'une compromission antérieure dont vous n'aviez pas conscience.

**Action** :
- Audit complet de l'infrastructure
- Reset de tous les credentials (DB, API, admin)
- Notifier les utilisateurs concernés
- Déclaration RGPD si applicable

## Que faire si vous êtes compromis : les 7 étapes

### 1. Garder son calme et préserver les preuves
Ne supprimez rien tout de suite. Faites un **snapshot complet** du système (image disque) pour analyse forensique ultérieure.

### 2. Isoler
Mettez le site en mode maintenance. Si compromission grave : couper le serveur du réseau.

### 3. Identifier le vecteur d'entrée
- Quels logs ?
- Quelle vulnérabilité a été exploitée ?
- Quand l'attaquant est-il entré ?

### 4. Nettoyer
- Restaurer depuis une sauvegarde **antérieure à la compromission** (pas la dernière, qui est probablement déjà infectée)
- Patcher la vulnérabilité d'origine
- Auditer tous les comptes et resetter les credentials

### 5. Auditer
- Tous les autres systèmes connectés au site compromis (DB, API, etc.)
- Vérifier qu'aucune **backdoor** n'a été laissée

### 6. Communiquer
- Aux utilisateurs si données personnelles concernées
- À la CNIL dans les 72h si fuite RGPD
- À votre assurance cyber

### 7. Renforcer
- Implémenter ce qui aurait permis d'éviter cette compromission
- Mettre en place un monitoring continu (audit d'intégrité, WAF, alertes)
- Plan d'incident à jour pour la prochaine fois

## Prévenir vaut mieux que guérir

Si vous lisez cet article par curiosité (et pas suite à un incident), félicitations — vous êtes proactif.

[ARGUS Security](/) ne détecte pas les compromissions en cours (ça nécessite un agent sur votre serveur), mais il détecte **les vulnérabilités qui permettent les compromissions futures** : versions de logiciels obsolètes, sous-domaines exposés, configurations faibles.

C'est la première ligne de défense : empêcher l'attaquant d'entrer.

**Une heure d'audit préventif vaut mieux que 100 heures de réponse à incident.**
