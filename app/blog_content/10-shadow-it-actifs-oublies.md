---
title: Shadow IT — comment trouver les actifs oubliés de votre entreprise
slug: shadow-it-actifs-oublies-entreprise
description: Le Shadow IT, c'est tout ce que personne ne maintient officiellement chez vous. C'est aussi la première cible des attaquants. Voici comment le cartographier.
keywords: shadow IT, actifs oubliés entreprise, cartographie SI, inventaire informatique, surveillance surface attaque
date: 2026-05-13
reading_time: 6 min
category: Stratégie
---

Le **Shadow IT** désigne tous les actifs informatiques de votre entreprise qui ne sont **pas officiellement gérés** : un site lancé par le marketing sans en parler à l'IT, un sous-domaine créé pour une campagne et oublié, une instance cloud abandonnée, un compte SaaS d'ancien employé.

Le shadow IT n'est pas malveillant. C'est juste **ce que personne ne suit**. Et c'est exactement pour ça que c'est la **première cible** des attaquants.

## Pourquoi le shadow IT est si dangereux

Quand votre équipe IT déploie un nouveau serveur, elle :
- Le maintient à jour
- Le surveille
- Met en place du monitoring
- Patche les CVE quand elles sortent

Quand le marketing déploie un site WordPress pour une campagne ponctuelle et l'oublie après 6 mois :
- Plus de mises à jour de WordPress
- Plus de patches de plugins
- Plus de monitoring
- Personne ne regarde les logs

**Résultat** : ce site devient une **bombe à retardement**. Un attaquant qui découvre `campagne2022.entreprise.com` y déploie ses exploits, prend la main, et utilise le serveur pour pivoter vers le reste de votre infrastructure.

## Les 7 types de shadow IT classiques

### 1. Anciens sites web et campagnes

**Pattern** : domains, sous-domaines, ou sous-répertoires créés pour des opérations marketing ponctuelles.

**Exemples** : `summer-sale-2023.entreprise.com`, `concours-rentree.entreprise.com`, `entreprise.com/landing-promo/`.

**Risques** : versions obsolètes de WordPress/Drupal, plugins vulnérables, configurations de test.

### 2. Environnements de dev/test publics

**Pattern** : un développeur lance une instance pour tester, oublie d'éteindre.

**Exemples** : `dev2.entreprise.com`, `staging-new.entreprise.com`, `feature-xyz.preview.entreprise.com`.

**Risques** : credentials hardcodés, données de prod, messages d'erreur verbeux, comptes admin/test faibles.

### 3. Instances cloud abandonnées

**Pattern** : VM AWS/Azure/GCP lancées pour un projet, plus utilisées mais facturées.

**Risques** : pas seulement le coût — versions OS obsolètes, services par défaut exposés.

### 4. Comptes SaaS d'ex-employés

**Pattern** : un employé partait, ses accès Gmail/Slack/Notion/Salesforce n'ont jamais été désactivés.

**Risques** : compromission via mot de passe leaké, exfiltration de données, attaques d'ingénierie sociale au nom de l'entreprise.

### 5. APIs internes exposées par erreur

**Pattern** : une API conçue pour être interne se retrouve accessible depuis Internet (mauvaise config firewall, certificat wildcard, etc.).

**Risques** : endpoints non documentés, authentifications faibles, fuite de données métier.

### 6. Bases de données de backup

**Pattern** : un dump SQL ou Redis copié sur un serveur "pour faire un test" et jamais supprimé.

**Risques** : exposition directe de données structurées (clients, commandes, mots de passe hashés).

### 7. Outils internes accessibles publiquement

**Pattern** : Jenkins, GitLab, SonarQube installés "rapidement" sans firewall.

**Risques** : énormes. Voir notre [article dédié sur les sous-domaines à risque](/blog/sous-domaines-risque-admin-dev-old).

## Comment cartographier votre shadow IT

### Méthode 1 — Reconnaissance OSINT externe

C'est ce qu'un attaquant ferait sur vous. Combiner plusieurs sources :

1. **Certificate Transparency logs** (crt.sh) : liste tous les certs SSL émis pour votre domaine, donc tous vos sous-domaines même internes.
2. **Wayback Machine** (archive.org) : pages historiques qui peuvent révéler des URL oubliées encore accessibles.
3. **Shodan** : recherche par IP/ASN/domaine, révèle les services exposés.
4. **Bases publiques DNS** : SecurityTrails, DNSDB.
5. **GitHub search** : `org:votre-entreprise` peut révéler des configs hardcodées, des secrets leakés.

[ARGUS Security](/) combine ces sources et vous donne en 60 secondes la liste complète de vos sous-domaines actifs.

### Méthode 2 — Inventaire interne croisé

À faire en interne en complément :

- **DNS** : listez tous vos enregistrements DNS chez votre registrar
- **Cloud accounts** : exportez les instances de chaque compte AWS/Azure/GCP
- **SaaS** : auditez les comptes utilisateurs dans Google Workspace, Microsoft 365, Slack, etc.
- **Domaines** : vérifiez tous les domaines achetés par l'entreprise (souvent éparpillés sur plusieurs registrars)
- **Certificats** : auditez votre fournisseur SSL pour voir tous les certs émis

### Méthode 3 — Sources comportementales

- **Logs DNS** : si vous avez un DNS interne, vous voyez tous les domaines requêtés (potentiel shadow SaaS)
- **Firewall logs** : trafic sortant inhabituel = service shadow utilisé
- **Factures cloud** : recherchez les lignes que vous ne reconnaissez pas

## La stratégie de remediation

Une fois la liste établie, classez en 3 catégories :

### À tuer immédiatement (50% des cas typiques)

- Sites de campagne terminée
- Environnements de test non utilisés
- Comptes ex-employés
- Anciennes API remplacées

**Action** : désactiver, fermer, supprimer.

### À officialiser (30% des cas)

- Outils utilisés activement par une équipe mais sans gouvernance IT
- Sites maintenus de facto par leur créateur

**Action** : intégrer dans le périmètre IT officiel, patcher, sécuriser, monitorer.

### À cloisonner (20% des cas)

- Outils nécessaires mais avec des risques
- Environnements de test inévitables

**Action** : VPN obligatoire, segmentation réseau, monitoring renforcé.

## Le cycle de prévention

Le shadow IT ne disparaît jamais. Il **réapparaît constamment** parce que les besoins business évoluent plus vite que les processus IT.

**Bonnes pratiques** :

### Process d'achat / déploiement

- Toute commande de domaine, SSL, instance cloud doit passer par un processus light avec validation IT (même asynchrone)
- Notification automatique à l'IT pour toute nouvelle dépense cloud > X€

### Audit régulier

- **Mensuel** : scan externe automatisé de vos domaines (ARGUS le fait)
- **Trimestriel** : revue des comptes SaaS (combien d'utilisateurs ? les ex-employés sont-ils tous désactivés ?)
- **Annuel** : audit complet de l'inventaire IT (humains + automatisé)

### Empowerment des équipes business

- Faciliter le passage par l'IT plutôt que le contourner (souvent, le shadow IT vient de la lenteur perçue de l'IT)
- Provider un catalogue d'outils approuvés
- Avoir une "fast track" pour les besoins urgents

## Pourquoi l'audit externe est complémentaire de l'audit interne

L'audit interne (DNS, cloud, factures) trouve ce que vous **connaissez à moitié**.

L'audit externe (OSINT) trouve ce que vous **avez complètement oublié** : un sous-domaine acheté il y a 5 ans par un employé parti depuis, un certificat SSL généré pour une POC abandonnée, un service exposé par un firewall mal configuré il y a 2 ans.

C'est exactement ce que voient les attaquants. Et c'est pour ça qu'il est précieux.

[ARGUS Security](/) fait cette reconnaissance externe en 60 secondes — vous voyez immédiatement ce qui est exposé à votre nom, ce qui devrait l'être, et ce qui ne devrait absolument pas l'être.

**Le shadow IT, c'est la dette technique invisible. Plus on la laisse s'accumuler, plus le rattrapage est douloureux.**
