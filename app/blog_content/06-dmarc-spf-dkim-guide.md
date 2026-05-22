---
title: DMARC, SPF, DKIM — le guide complet pour configurer la sécurité email de votre domaine
slug: dmarc-spf-dkim-configuration-guide
description: Sans SPF, DKIM et DMARC, n'importe qui peut envoyer un email au nom de votre domaine. Voici comment les configurer correctement, étape par étape.
keywords: DMARC configuration, SPF DKIM DMARC, sécurité email entreprise, phishing protection, anti-spoofing email
date: 2026-05-17
reading_time: 9 min
category: Email
---

Si vous envoyez ou recevez des emails depuis votre nom de domaine, vous **devez** avoir SPF, DKIM et DMARC configurés. Sans eux, n'importe qui peut envoyer des emails au nom de votre marque et :
- Phishing vos clients ("votre facture est en pièce jointe")
- Arnaque BEC sur votre comptabilité ("nouvelle RIB à utiliser")
- Spam massif (vos emails légitimes finiront en spam folder)

Ce guide explique le pourquoi et le comment, sans jargon inutile.

## Pourquoi c'est obligatoire en 2026

Depuis février 2024, **Google et Yahoo refusent ou marquent en spam** les emails envoyés en masse (>5000/jour) sans authentification correcte. Microsoft suit le mouvement.

Conséquence : si votre newsletter ou vos emails transactionnels (factures, confirmations de commande) n'ont pas SPF/DKIM/DMARC correctement configurés, ils finissent **en spam** chez vos clients. Vous perdez du business sans le savoir.

Au-delà du business : sans DMARC, **votre domaine est usurpable** par n'importe qui. C'est la base de 90% des attaques BEC qui coûtent en moyenne 65 000€ aux PME victimes.

## Comprendre les 3 protocoles en 2 minutes

### SPF (Sender Policy Framework)

C'est une **liste blanche** : quels serveurs ont le droit d'envoyer des emails au nom de votre domaine.

**Exemple** : si vous utilisez Google Workspace + Mailchimp + Resend pour vos emails, votre SPF doit autoriser les serveurs de ces 3 services.

**Format DNS** :
```
v=spf1 include:_spf.google.com include:servers.mcsv.net include:amazonses.com ~all
```

- `v=spf1` : version du protocole
- `include:` : autorise les serveurs du fournisseur cité
- `~all` : soft fail (les autres serveurs sont suspects mais pas bloqués)
- `-all` : hard fail (les autres sont rejetés direct — plus strict)

### DKIM (DomainKeys Identified Mail)

C'est une **signature cryptographique** sur chaque email envoyé. Le destinataire vérifie que :
1. L'email vient bien d'un serveur autorisé (clé publique publiée dans votre DNS)
2. Le contenu n'a pas été modifié en route

Chaque service email a son propre "sélecteur" DKIM. Vous publiez une clé publique dans le DNS pour chaque service.

**Format DNS** (exemple pour Google) :
```
google._domainkey.votredomaine.com TXT "v=DKIM1; k=rsa; p=MIIBIjANBgkqhki..."
```

### DMARC (Domain-based Message Authentication, Reporting and Conformance)

C'est la **politique** qui dit aux serveurs receveurs quoi faire si SPF ou DKIM échouent sur un email prétendant venir de votre domaine.

**Format DNS** :
```
_dmarc.votredomaine.com TXT "v=DMARC1; p=quarantine; rua=mailto:reports@votredomaine.com; pct=100"
```

- `p=` : la politique
  - `none` : ne rien faire, juste rapporter (mode "monitoring", à utiliser pour démarrer)
  - `quarantine` : mettre en spam
  - `reject` : rejeter complètement
- `rua=` : adresse qui reçoit les rapports agrégés (essentiel pour ajuster)
- `pct=100` : appliquer la politique à 100% des emails (peut commencer à 10% pour tester)

## La configuration étape par étape

### Étape 1 — Audit de l'existant (5 min)

Avant de configurer quoi que ce soit, vérifiez ce que vous avez déjà :

1. Allez sur [mxtoolbox.com](https://mxtoolbox.com) ou utilisez le scan de [ARGUS](/)
2. Recherchez votre domaine
3. Vérifiez les enregistrements SPF, DKIM, DMARC

**Cas classiques** :
- Aucun des 3 → priorité absolue, configurez maintenant
- SPF seul → ajoutez DKIM et DMARC
- Tous présents mais DMARC en p=none → bien, mais durcissez en p=quarantine après 30 jours

### Étape 2 — Lister vos services email (10 min)

Quels services envoient des emails au nom de votre domaine ?
- Service de messagerie principal (Google Workspace, Microsoft 365, ProtonMail…)
- Newsletter (Mailchimp, Brevo, ActiveCampaign…)
- Transactionnel (Resend, Postmark, SendGrid, AWS SES…)
- CRM (HubSpot, Salesforce…)
- Outils SaaS (Zendesk, Intercom…)

**Pour chacun**, vous devez :
- L'ajouter au SPF
- Récupérer sa clé DKIM et la publier dans le DNS

Sans ça, ses emails seront rejetés par DMARC.

### Étape 3 — Configurer SPF (15 min)

Allez chez votre registrar/DNS provider (OVH, Cloudflare, Gandi, Hostinger…).

Ajoutez ou modifiez l'enregistrement TXT à la racine :

```
@   TXT   "v=spf1 include:_spf.google.com include:amazonses.com ~all"
```

**Règles importantes** :
- **Un seul enregistrement SPF par domaine** (sinon Outlook le rejette)
- Maximum **10 lookups DNS** (chaque `include:` compte 1, attention à pas exploser)
- Commencez par `~all` (soft fail), passez à `-all` après 30 jours sans problèmes

### Étape 4 — Configurer DKIM (15 min)

Pour chaque service email, suivez sa procédure :

**Google Workspace** :
1. Console admin → Apps → Google Workspace → Gmail → Authentifier les emails
2. Générer la clé DKIM 2048-bit
3. Copier le sélecteur (généralement "google") et la valeur
4. Publier dans le DNS : `google._domainkey.votredomaine.com TXT "v=DKIM1;..."`

**Resend** (et services similaires) :
1. Dashboard → Domains → Add domain
2. Suivre les instructions pour ajouter le TXT DKIM
3. Vérifier que le statut passe au vert

**Mailchimp / SendGrid / Brevo** : même procédure, chaque service a sa doc.

### Étape 5 — Activer DMARC en mode monitoring (5 min)

Publiez un enregistrement DMARC qui ne bloque rien mais qui rapporte tout :

```
_dmarc   TXT   "v=DMARC1; p=none; rua=mailto:dmarc@votredomaine.com; pct=100"
```

Pendant 2-4 semaines, vous allez recevoir des **rapports XML quotidiens** de Google, Microsoft, etc., qui listent tous les emails envoyés au nom de votre domaine et leur authentification.

**Outil pratique** : utilisez [Postmark DMARC](https://dmarc.postmarkapp.com/) (gratuit) ou Valimail Monitor pour parser les XML automatiquement et avoir un dashboard lisible.

### Étape 6 — Durcir DMARC après monitoring (1 mois plus tard)

Si vos rapports montrent que **tous vos emails légitimes passent** SPF et DKIM, passez DMARC en mode plus strict :

```
_dmarc   TXT   "v=DMARC1; p=quarantine; rua=mailto:dmarc@votredomaine.com; pct=100"
```

Puis après 1 nouveau mois sans plainte de clients (emails manquants en spam) :

```
_dmarc   TXT   "v=DMARC1; p=reject; rua=mailto:dmarc@votredomaine.com; pct=100"
```

C'est l'objectif final : **rejet pur et simple** de toute usurpation.

## Les pièges classiques

### Plusieurs enregistrements SPF

Symptôme : Outlook rejette vos emails même si SPF est censé être bon.

Cause : vous avez deux TXT SPF à la racine (souvent un de votre hébergeur et un que vous avez ajouté).

**Solution** : fusionner en un seul.

### Limite de 10 lookups

Symptôme : les nouveaux services ne marchent plus quand ajoutés au SPF.

Cause : chaque `include:` qui contient lui-même des `include:` compte ses propres lookups. Google = 4, Mailchimp = 3, etc.

**Solution** : utiliser un service "SPF flattening" comme Cloudflare ou EasyDMARC.

### Sous-domaines oubliés

Symptôme : votre app sous `app.votredomaine.com` envoie des emails qui finissent en spam alors que le domaine principal va bien.

Cause : DMARC à la racine couvre `@votredomaine.com` mais pas `@app.votredomaine.com` sans configuration explicite.

**Solution** : publier un DMARC séparé sur chaque sous-domaine, ou utiliser `sp=` (subdomain policy) dans le DMARC racine.

### DKIM clé compromise

Si quelqu'un a accès à votre clé privée DKIM (ex: leak GitHub), il peut signer des emails frauduleux au nom de votre domaine.

**Solution** : rotation périodique des clés DKIM (générer une nouvelle paire et publier le nouveau sélecteur).

## Vérifier en continu

La configuration SPF/DKIM/DMARC n'est pas un projet "one-shot". Ajoutez un service de monitoring qui vous alerte si :
- Un nouveau service envoie des emails non authentifiés (SPF fail)
- Vos clés DKIM expirent ou sont mal configurées
- Le volume d'emails rejetés par DMARC augmente anormalement

[ARGUS Security](/) inclut un audit SPF/DKIM/DMARC dans chaque scan de domaine — vous voyez en 60 secondes si votre configuration est correcte ou si vous êtes exposé au spoofing.

**Sans SPF/DKIM/DMARC, votre domaine est offert sur un plateau à n'importe quel attaquant. Avec, vous êtes la cible la plus difficile possible.**
