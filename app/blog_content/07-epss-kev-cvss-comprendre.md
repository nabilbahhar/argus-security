---
title: EPSS, KEV, CVSS — décoder les scores de vulnérabilité (et lesquels regarder vraiment)
slug: epss-kev-cvss-comprendre-vulnerabilites
description: Tous les outils de sécurité parlent de CVSS, EPSS, KEV. Voici ce que ça veut dire, lequel utiliser pour prioriser vos patchs, et les pièges classiques.
keywords: EPSS expliqué, KEV CISA, CVSS score, priorisation vulnérabilités, CVE exploitable
date: 2026-05-16
reading_time: 8 min
category: Vulnérabilités
---

Vous lancez un scan de sécurité. Le rapport vous donne 350 vulnérabilités avec des scores incompréhensibles : CVSS 9.8, EPSS 87%, KEV active. Lesquelles patcher en premier ? Toutes ne sont pas égales.

Ce guide explique chaque score, leur **vraie signification**, et comment construire une **stratégie de priorisation** qui ne vous fait pas tout patcher en panique.

## Le problème de la priorisation

Une grande entreprise typique a **des milliers de vulnérabilités identifiées** sur son infrastructure à un moment donné. Patcher tout est impossible :
- Certains patchs cassent les apps métier
- Certains nécessitent un redémarrage de serveur
- L'équipe IT n'a pas la bande passante

Il faut **prioriser**. La bonne priorisation :
- Patcher en urgence ce qui sera exploité dans les 7 jours
- Planifier dans le mois ce qui peut l'être
- Ignorer (ou patcher au prochain cycle régulier) ce qui n'a pas de chance d'être exploité

C'est là qu'interviennent les scores.

## CVSS — Le score "gravité technique"

**Common Vulnerability Scoring System**, créé par le FIRST. Version actuelle : CVSS 3.1 (et v4 émergent).

**Échelle** : 0 à 10.
- 0-3.9 : Low
- 4-6.9 : Medium
- 7-8.9 : High
- 9-10 : Critical

### Comment il est calculé

Le score combine plusieurs facteurs :
- **Attack Vector** : à distance, réseau local, physique ?
- **Attack Complexity** : facile ou difficile à exploiter ?
- **Privileges Required** : faut-il être déjà admin, simple user, ou rien ?
- **User Interaction** : faut-il que la victime clique sur un lien ?
- **Scope** : peut-on pivoter vers d'autres systèmes ?
- **Impact** : sur la confidentialité, l'intégrité, la disponibilité

### Le problème de CVSS

CVSS mesure la **gravité théorique** d'une vulnérabilité, **pas la probabilité réelle d'exploitation**.

**Exemple concret** : une CVE avec CVSS 10.0 mais qui nécessite un exploit complexe non public et qui ne touche que les Windows Server 2008 sera moins urgente qu'une CVE CVSS 7.5 mais qui a un exploit public sur GitHub et qui est massivement utilisée.

CVSS répond à **"si c'est exploité, combien ça fait mal ?"**. Pas à **"est-ce que ça va être exploité ?"**.

## EPSS — Le score "probabilité d'exploitation"

**Exploit Prediction Scoring System**, géré par le FIRST aussi (depuis 2021).

**Échelle** : 0% à 100%. C'est la **probabilité statistique** que la CVE soit exploitée **dans les 30 prochains jours**, basée sur un modèle ML entraîné sur les exploitations observées dans la nature.

### Ce qui fait monter EPSS

- **Exploit public disponible** (sur Exploit-DB, GitHub, Metasploit)
- **Discussions dans les forums** (clear web, dark web)
- **CVE récente** (plus exploitée dans les 30 premiers jours)
- **Cible populaire** (WordPress, Apache, Microsoft Exchange…)
- **Mentions dans la threat intel** (groupes connus l'utilisent)

### L'avantage d'EPSS

EPSS répond à la vraie question : **"est-ce que cette CVE sera exploitée chez moi bientôt ?"**

**Statistique** : moins de 5% des CVE ont un EPSS > 50%. La grande majorité ont un EPSS proche de 0 (gravité théorique élevée mais zéro exploitation observée).

### Seuils utiles

- **EPSS > 80%** : à patcher dans les 24h
- **EPSS 50-80%** : à patcher dans la semaine
- **EPSS 10-50%** : à planifier dans le mois
- **EPSS < 10%** : cycle de patch normal (mensuel)

## KEV — Le catalogue "exploit déjà vu en production"

**Known Exploited Vulnerabilities**, géré par la **CISA** (US Cybersecurity & Infrastructure Security Agency).

C'est une **liste binaire** : une CVE est dans KEV **ou** elle n'y est pas. **Pas de score**.

### Quand une CVE entre dans KEV

La CISA ajoute une CVE à KEV quand elle a **preuves d'exploitation active** dans la nature contre des cibles **réelles**. Les sources :
- Rapports de threat intel (Mandiant, CrowdStrike, Microsoft, etc.)
- Incidents reportés par les agences gouvernementales US
- Détection sur les honeypots

### Pourquoi KEV est l'indicateur le plus important

Si une CVE est dans KEV, ça veut dire **des attaquants vraiment exploitent cette faille en ce moment** contre des entreprises comme la vôtre.

Les agences fédérales américaines ont **un délai légal de 15 jours** pour patcher toute CVE entrée en KEV.

Vous devriez avoir le même réflexe : **toute CVE KEV active sur votre infrastructure = patch dans les 7 jours**, peu importe le reste.

## La stratégie de priorisation gagnante

Combinez les 3 scores en arbre de décision :

### 1. CVE dans KEV → URGENT (1 semaine max)

Indépendamment de CVSS ou EPSS, si la CISA dit qu'elle est exploitée activement, vous êtes en zone rouge. Patchez.

### 2. CVE pas KEV mais EPSS > 50% → IMPORTANT (1 mois max)

Forte probabilité d'exploitation prochaine. Planifiez le patch dans votre prochain cycle de release.

### 3. CVE pas KEV, EPSS < 50%, CVSS > 9 → NORMAL (3 mois)

Gravité théorique élevée mais pas d'exploitation observée. Patchez dans votre cycle de release standard.

### 4. CVE pas KEV, EPSS < 10%, CVSS < 7 → BAS (cycle régulier)

Probabilité d'exploitation faible et gravité limitée. Patchez au prochain cycle de maintenance régulier.

## Les pièges classiques

### Patcher tout ce qui est CVSS > 7

C'est ce que font 80% des entreprises et c'est **épuisant et inefficace**. Vous patchez des CVE qui ne seront jamais exploitées tout en laissant des CVE KEV active non patchées.

**Mieux** : commencer par KEV active, puis EPSS > 50%.

### Ignorer EPSS parce que "trop nouveau"

EPSS a été lancé en 2021 mais son modèle est constamment ré-entraîné. Sa précision est aujourd'hui **excellente** (5x meilleure que CVSS pour prédire les exploits réels).

### Confondre KEV et CISA Top Routinely Exploited

CISA publie plusieurs listes. La **"Known Exploited Vulnerabilities Catalog"** (KEV) est la liste à jour des CVE actuellement exploitées. À ne pas confondre avec la "Top Routinely Exploited Vulnerabilities" (rapport annuel).

### Ne pas vérifier EPSS qui change dans le temps

EPSS peut évoluer rapidement. Une CVE à 5% peut monter à 85% en quelques jours si un exploit public apparaît. **Re-checker régulièrement** (l'API EPSS du FIRST est gratuite, beaucoup d'outils l'intègrent en temps réel).

## Comment ARGUS utilise ces scores

[ARGUS Security](/) enrichit automatiquement chaque vulnérabilité détectée avec :
- **CVSS** (depuis la NVD)
- **EPSS** (depuis l'API FIRST, mise à jour quotidienne)
- **KEV** (depuis le catalogue CISA, mis à jour en temps réel)

Et utilise un scoring intelligent pour vous présenter **en priorité** les vulnérabilités qui combinent KEV + EPSS élevé. Pas une liste plate de "350 CVE à corriger".

**La vraie compétence en sécurité n'est pas de patcher beaucoup. C'est de patcher ce qui va être exploité, avant qu'il ne le soit.**
