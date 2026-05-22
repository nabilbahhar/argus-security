---
title: Auditer la cybersécurité de sa PME quand on n'est pas technicien (guide dirigeant)
slug: audit-cybersecurite-pme-dirigeant
description: Vous êtes CEO, fondateur ou directeur d'une PME. Voici comment évaluer concrètement votre exposition cyber sans dépendre d'un prestataire.
keywords: audit cybersécurité PME, dirigeant cybersécurité, audit cyber dirigeant, sécurité site web PME
date: 2026-05-20
reading_time: 8 min
category: Stratégie
---

Vous dirigez une PME. Vous savez que la cybersécurité est importante, mais vous n'avez ni RSSI ni équipe IT dédiée. Quand vous demandez un audit à un prestataire, le devis est entre 5000 et 30000€ et le rapport est un PDF de 80 pages que vous ne comprenez pas.

Voici comment faire un **vrai diagnostic cyber** de votre entreprise en 2 heures, sans expertise technique, et avec une feuille de route claire.

## Pourquoi l'audit cyber d'un dirigeant est différent

Quand un RSSI fait un audit, il cherche **toutes** les failles techniques pour les remonter à l'équipe IT.

Quand un dirigeant veut auditer, il a besoin de répondre à 3 questions business :
1. **Suis-je une cible facile ?** (par opposition à : "ai-je 47 vulnérabilités moyennes")
2. **Qu'est-ce qui me coûterait le plus si je suis attaqué ?**
3. **Quelles sont les 3 actions à faire en priorité (selon mon budget) ?**

Cet article vise ces 3 questions, pas la liste exhaustive de CVE.

## Étape 1 — La carte de votre surface d'attaque (15 min)

La "surface d'attaque" = tout ce qui est accessible depuis Internet et qui appartient à votre entreprise. Vous ne pouvez pas protéger ce que vous ne voyez pas.

### Inventaire à faire

1. **Vos noms de domaine** : combien en avez-vous ? Souvent une PME en a 5-10 (domaine principal, variations marques, redirections oubliées).
2. **Vos sites web** : combien sont vraiment maintenus ? Le site principal probablement. Mais l'ancien site, le blog "campagne 2022", le portail RH ?
3. **Vos boîtes email** : tous les comptes ont-ils un mot de passe fort + 2FA ?
4. **Vos services cloud** : Microsoft 365, Google Workspace, Dropbox, partage de fichiers ?
5. **Vos comptes réseaux sociaux** : avec quels emails sont-ils liés ? Sont-ils sécurisés ?

> **Test rapide** : lancez un scan de votre domaine principal sur [ARGUS Security](/). En 60 secondes, vous verrez tous les sous-domaines actifs liés à votre marque. Vous serez surpris.

### Ce qu'il faut chercher

- Sous-domaines avec des noms suspects : `bo.`, `admin.`, `old.`, `dev.`, `test.`
- Sites avec une **technologie ancienne** (WordPress 5.x, PHP 7.x = pas de patch depuis 2022)
- **Certificats SSL expirés** ou bientôt expirés
- Sites avec une **page "erreur" générique** (souvent abandonnés)

## Étape 2 — Le diagnostic email (15 min)

L'email est le vecteur n°1 d'attaque contre les PME (phishing, BEC, ransomware). Le diagnostic est rapide.

### 3 réglages à vérifier

Sur votre domaine principal, vous devez avoir trois enregistrements DNS configurés :

1. **SPF** (Sender Policy Framework) : liste les serveurs autorisés à envoyer des emails en votre nom.
2. **DKIM** (DomainKeys Identified Mail) : signe cryptographiquement chaque email sortant.
3. **DMARC** : politique qui dit aux destinataires quoi faire si SPF et DKIM échouent.

**Sans ces trois réglages**, n'importe qui peut envoyer un email à vos clients en se faisant passer pour vous. C'est ainsi que démarrent la plupart des arnaques BEC (Business Email Compromise) qui coûtent en moyenne **65 000€ par incident** aux PME.

### Le test gratuit

Demandez à un outil de scan (ARGUS le fait, MXToolbox aussi) de vérifier votre domaine. En 10 secondes vous savez si vous êtes à risque.

Si SPF ou DMARC sont absents : **demandez à votre prestataire DNS de les ajouter ce mois-ci**. C'est 30 minutes de travail.

## Étape 3 — Les comptes utilisateurs (20 min)

70% des incidents cyber passent par un **compte compromis**, pas par une faille technique. C'est plus efficace de durcir vos comptes que d'auditer votre code.

### Le minimum vital

- **2FA obligatoire** sur : email, banque, hébergement, comptes admin, Microsoft 365 / Google Workspace
- **Mots de passe uniques** par service (utilisez un gestionnaire : Bitwarden, 1Password)
- **Audit des accès** : qui a accès à quoi dans votre entreprise ? Faites le tour, supprimez les comptes des ex-employés
- **Privilèges minimaux** : un commercial n'a pas besoin d'accès admin à votre CMS

### Le test concret

Demandez-vous : *si demain l'un de mes employés clique sur un lien de phishing et donne son mot de passe, qu'est-ce que l'attaquant peut faire ?*
- Si la réponse est "tout" → vous avez un gros problème
- Si la réponse est "rien de critique sans 2FA" → vous êtes au bon endroit

## Étape 4 — Les sauvegardes (10 min)

C'est le filet de sécurité ultime. Si vous êtes ransomwarisé demain, **les sauvegardes sont ce qui détermine si vous payez ou non**.

### Règle du 3-2-1

- **3 copies** de vos données importantes
- **2 supports différents** (disque local + cloud)
- **1 copie hors ligne** (que le ransomware ne peut pas chiffrer)

### Test du jour

Quand avez-vous **testé la restauration** de vos sauvegardes pour la dernière fois ? Si la réponse est "jamais" ou "il y a plus de 6 mois", c'est urgent. Une sauvegarde non testée = une sauvegarde qui peut ne pas marcher.

## Étape 5 — Le diagnostic des prestataires (15 min)

Vous êtes responsable de la sécurité de vos données — même quand elles sont chez un prestataire (Cloud, hébergement, CRM, etc.). Listez vos prestataires critiques et posez-leur 5 questions :

1. **Où sont stockées mes données ?** (pays, fournisseur cloud)
2. **Que se passe-t-il si vous êtes attaqués ?** (continuité de service, notification)
3. **Avez-vous une certification ISO 27001 ou équivalent ?**
4. **Comment puis-je récupérer mes données si je quitte ?**
5. **Êtes-vous assurés contre les cyberattaques ?**

Si plusieurs réponses sont vagues : prévoyez une migration vers un prestataire qui prend la sécurité au sérieux.

## Étape 6 — Le plan d'action (30 min)

Après ce diagnostic, vous devriez avoir une liste de 10-20 actions. Hiérarchisez-les en 3 buckets :

### Urgent (à faire cette semaine)
- Corriger SPF/DKIM/DMARC absents
- Activer le 2FA sur les comptes critiques
- Désactiver les sites/sous-domaines oubliés
- Mettre à jour les versions de WordPress/Drupal/etc. en fin de vie

### Important (ce trimestre)
- Mettre en place un gestionnaire de mots de passe d'entreprise
- Audit complet des accès employés
- Tester la restauration de sauvegardes
- Formation phishing pour vos équipes

### Stratégique (cette année)
- Souscrire une assurance cyber
- Mettre en place un EDR sur tous les postes
- Migration vers un prestataire d'hébergement sécurisé
- Audit complet par un cabinet externe

## Combien ça coûte ?

Bonne nouvelle : les actions urgentes sont **gratuites ou quasi-gratuites**. SPF/DMARC se configurent en 30 minutes par votre prestataire DNS. Le 2FA est gratuit sur tous les services majeurs.

Les actions importantes coûtent **entre 50 et 500€/mois** (gestionnaire de mots de passe, sauvegarde cloud).

Les actions stratégiques coûtent **plusieurs milliers d'euros par an** mais sont des investissements de protection face à des incidents qui coûtent 50 000 à 500 000€ en moyenne pour une PME.

## Pour aller plus loin

[ARGUS Security](/) fait gratuitement l'étape 1 (cartographie de votre surface d'attaque) et l'étape 2 (diagnostic email) en 60 secondes. Pour les étapes 3 à 6, vous pouvez les faire vous-même avec ce guide, ou nous contacter pour un accompagnement personnalisé via notre [plan Entreprise](/pricing).

Vous n'avez pas besoin d'être expert pour commencer. La sécurité, c'est 80% de discipline et 20% de technique. La discipline, c'est vous.
