---
title: Comment vérifier les ports ouverts de votre serveur (sans installer Nmap)
slug: verifier-ports-ouverts-serveur-web
description: Les ports ouverts sont la première chose qu'un attaquant énumère. Voici comment auditer votre exposition, ce qui devrait être fermé, et les outils gratuits.
keywords: ports ouverts serveur, scanner ports site web, audit ports TCP, vérifier ports exposés, port scanner gratuit
date: 2026-05-14
reading_time: 6 min
category: Reconnaissance
---

Quand un attaquant cible votre serveur, sa **première action** est d'énumérer les ports ouverts. Chaque port ouvert = un service exposé = une porte potentielle. Voici comment auditer la vôtre, sans devenir admin système.

## Comprendre les ports en 2 minutes

Un serveur expose des services sur des **ports numérotés** de 1 à 65535. Quelques exemples standards :
- **22** : SSH (administration à distance)
- **25** : SMTP (envoi d'emails)
- **80** : HTTP (web non chiffré)
- **443** : HTTPS (web chiffré)
- **3306** : MySQL
- **5432** : PostgreSQL
- **6379** : Redis
- **27017** : MongoDB

**Règle simple** : si un service n'a pas besoin d'être accessible depuis Internet, son port doit être **fermé** ou **filtré** par firewall.

## Les ports qui doivent être ouverts publics

Pour un serveur web standard, seuls **2 ports** devraient être accessibles depuis Internet :
- **80** : HTTP (généralement pour rediriger vers HTTPS)
- **443** : HTTPS

C'est tout. Tout le reste devrait être accessible **uniquement depuis** :
- Votre VPN d'entreprise
- Votre IP de bureau (allowlist)
- Le réseau interne (RDS, RDP)

## Les ports qui ne devraient JAMAIS être publics

Voici la liste rouge — si un de ces ports est ouvert vers Internet sur votre serveur, vous êtes à risque immédiat :

### Bases de données
- **3306** (MySQL/MariaDB)
- **5432** (PostgreSQL)
- **6379** (Redis)
- **27017** (MongoDB)
- **9200** (Elasticsearch)
- **5984** (CouchDB)

**Risque** : si la base n'a pas de mot de passe (très fréquent en config par défaut), un attaquant peut tout lire / tout supprimer / mettre du ransomware dessus. **Plus de 100 000 bases MongoDB et Elasticsearch sont accessibles sans auth sur Internet**.

### Outils d'administration
- **22** (SSH) — devrait être accessible uniquement par VPN/allowlist
- **3389** (RDP Windows) — brute-forcé en permanence
- **5900** (VNC)
- **2222** (SSH alternatif)
- **8000-9000** (admin panels divers)

**Risque** : brute-force massif 24/7. Une faille `BlueKeep` sur RDP a touché des millions d'entreprises.

### Services techniques exposés par erreur
- **8080** (proxy/admin web)
- **8443** (HTTPS alternatif souvent admin)
- **9001** (Jenkins)
- **5601** (Kibana)
- **3000** (Grafana)
- **6443** (Kubernetes API)
- **8181** (admin various)

**Risque** : configurations par défaut faibles, CVE non patchées, fuites d'informations.

### Services email
- **25** (SMTP) — ouvert public seulement si vous êtes serveur email
- **110** (POP3)
- **143** (IMAP)

**Risque** : si vous n'êtes pas un fournisseur email, ces ports doivent être fermés.

## Comment scanner vos ports

### Option 1 — Outils en ligne (le plus simple)

Plusieurs services gratuits font un scan rapide depuis l'extérieur :

- **[ARGUS Security](/)** : intègre un audit des ports dans le mode pentest (plan Essentiel+)
- **Shields Up** (Steve Gibson) : test simple des ports communs
- **MXToolbox** : utile pour les ports email

**Avantage** : aucune installation, scan depuis l'extérieur (= la vraie vue d'un attaquant).

### Option 2 — Nmap (l'outil de référence)

Si vous êtes un peu technique, Nmap est l'outil ultime. Installez-le ou utilisez la version web (Nmap Online).

**Commande basique** :
```
nmap -F votreserveur.com
```
(scanne les 100 ports les plus communs)

**Scan complet plus profond** :
```
nmap -sV -p- -T4 votreserveur.com
```
(tous les 65535 ports + détection de version, plus lent)

**Important** : ne scannez **que vos propres serveurs**, ou des cibles dont vous avez l'autorisation écrite. Scanner d'autres serveurs sans autorisation est une infraction pénale dans la plupart des pays.

### Option 3 — Shodan (la vue panoramique)

[Shodan](https://shodan.io) est un moteur de recherche qui scanne en continu tout Internet et indexe les services exposés. Cherchez votre IP ou votre domaine, vous verrez immédiatement ce qui est visible depuis l'extérieur.

**Avantage** : c'est aussi ce que voient les attaquants. Ils n'ont même pas besoin de scanner — Shodan a déjà tout indexé.

## Que faire des ports anormalement ouverts

### Si un port DB est public

**Action immédiate** :
1. Activer le firewall pour bloquer le port depuis Internet
2. Restreindre à `localhost` ou aux IPs de vos app servers uniquement
3. Vérifier qu'un mot de passe fort est défini
4. Auditer les logs pour voir si quelqu'un a déjà accédé

### Si SSH est public (port 22)

C'est courant mais à risque. **Au minimum** :
- Désactiver l'authentification par mot de passe (clés SSH uniquement)
- Désactiver root login direct
- Installer `fail2ban` pour bannir les IP qui brute-force
- Idéalement : derrière un VPN, jamais en direct

### Si RDP est public (port 3389)

**Plus dangereux** que SSH (cible facile pour ransomware). Idéalement :
- Passer derrière un VPN
- Sinon : changer le port (réduit le bruit mais ne sécurise pas vraiment), 2FA via Network Level Authentication

### Si un outil admin est exposé (Jenkins, Grafana, etc.)

- Vérifier qu'une authentification existe et qu'elle est forte
- Restreindre par IP allowlist
- Mieux : passer derrière un reverse proxy avec auth (Cloudflare Access, Authelia)

## Le firewall : votre meilleur ami

Tous les serveurs Linux ont `ufw` ou `firewalld`. Tous les serveurs Windows ont Windows Firewall. **Activez-les et restreignez par défaut**.

**Stratégie type pour un serveur web Linux** :

```bash
# Bloquer tout par défaut
ufw default deny incoming
ufw default allow outgoing

# Autoriser web public
ufw allow 80/tcp
ufw allow 443/tcp

# Autoriser SSH UNIQUEMENT depuis votre IP fixe / VPN
ufw allow from 1.2.3.4 to any port 22

# Activer
ufw enable
```

Plus aucun port non listé ne sera accessible. Toute exposition future = action consciente.

## Le monitoring continu

Faire un scan une fois et oublier ne suffit pas. Une mise à jour, un déploiement, un nouveau service installé par un dev peut **réouvrir un port** sans que vous le sachiez.

**Solutions** :
- **Audit régulier mensuel** avec Nmap/Shodan/ARGUS
- **Alerting Shodan** : Shodan peut vous alerter si un nouveau port apparaît sur votre IP
- **CSPM** (Cloud Security Posture Management) : outils enterprise qui surveillent en continu

[ARGUS Security](/) en mode pentest (plan Essentiel+) audite les ports communs de vos serveurs et vous flag les expositions suspectes avec un scénario d'attaque concret.

**Règle d'or** : tout port ouvert que vous n'avez pas explicitement décidé d'ouvrir est une faille en attente.
