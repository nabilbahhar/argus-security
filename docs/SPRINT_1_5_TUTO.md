# Sprint 1.5 — Features ASM pertinentes ajoutées

> Sprint qui ajoute les 5 features qui font la **vraie différence** vs Purplemet/CyCognito/Detectify.

---

## 🎯 Ce qui est nouveau vs Sprint 1

| Feature | Valeur business | Où ça apparaît |
|---|---|---|
| **🎖 Pupelmet Risk Score 0-100 + Grade A-F** | Un seul chiffre que CISO non-tech comprend | Hero en haut de la page scan |
| **📧 Audit DNS / SPF / DKIM / DMARC** | Indispensable conformité + anti-phishing | Section dédiée scan |
| **🔒 Audit TLS/SSL** (tlsx) | Certs expirés, protocoles obsolètes | Section dédiée scan |
| **⚡ Enrichissement EPSS + CISA KEV** | THE différentiateur premium cité par Purplemet | Colonnes EPSS + badge KEV ⚡ dans tableau vulns |
| **🎯 Nuclei tags élargis** | Détecte takeovers, fichiers leak, default-creds, panneaux admin | Augmente la richesse des findings |

---

## 🧱 Mise à jour (3 commandes)

Dans PowerShell :

```powershell
cd "C:\Users\NABIL BAHHAR\Projets Cyber\Outil pupelmet"

# 1. Sync : installe dnspython (nouvelle dépendance)
python -m uv sync

# 2. Télécharge le nouveau binaire tlsx (audit TLS approfondi)
powershell -ExecutionPolicy Bypass -File .\tools\install_tools.ps1

# 3. Lance le serveur (--reload reload auto à chaque modif)
python -m uv run uvicorn app.main:app --reload
```

Ouvre **http://127.0.0.1:8000**.

⚠️ **Reset DB** : si tu avais des scans Sprint 1 sauvegardés, les nouvelles colonnes (risk_score, kev_count, etc.) ne seront pas remplies. Pour repartir propre :

```powershell
del data\pupelmet.db
```

(Le fichier sera recréé automatiquement avec le schema 1.5.)

---

## 🚀 Workflow recommandé

### Test 1 — Scan rapide (sans Nuclei)
1. Va sur http://127.0.0.1:8000
2. Tape `compucom.ma`
3. **Décoche** Nuclei (pour gagner du temps)
4. Laisse **TLS coché**
5. Clique SCAN

⏱️ ~30-60 sec. Tu verras :
- **Risk Score + Grade** en hero
- **Section DNS / Email security** : SPF/DKIM/DMARC verdicts
- **Section TLS/SSL** : certs, protocoles
- Brief IA Claude
- Tableau d'actifs

### Test 2 — Scan complet (avec Nuclei)
1. Tape `compucom.ma` (ou n'importe quoi)
2. **Coche** Nuclei
3. Clique SCAN

⏱️ ~5-15 min. En plus du test 1, tu verras :
- **Tableau de vulnérabilités** trié intelligemment :
  - **Badge ⚡ KEV** sur les CVEs activement exploitées (CISA)
  - **Score EPSS %** : probabilité d'exploitation dans 30j
  - Le tri prend en compte KEV > EPSS > sévérité
- **Risk Score** ajusté avec pénalités KEV/EPSS visibles dans le breakdown

### Test 3 — Générer un email de prospection
1. Sur la page d'un scan terminé, en bas
2. Choisis le style (court / long / formel / direct)
3. Clique "► Générer"

L'IA fait l'email + LinkedIn + 5 réponses aux objections.

---

## 🧠 Pourquoi ces features sont les BONNES

### 1. Pupelmet Risk Score
**Inspiration** : Mozilla Observatory, score F de Purplemet (cité par Benjamin Krown).
**Pourquoi crucial** : un CISO non-tech ouvre l'app → voit "Grade F" → panic → call. Conversion immédiate.
**Algorithme** : transparent (visible dans le breakdown), pondère KEV, EPSS, severity, DNS, TLS.

### 2. DNS / SPF / DKIM / DMARC
**Inspiration** : MXToolbox, Hardenize.
**Pourquoi crucial** : 95% des phishings exploitent l'absence de DMARC. Aucun ASM "grand" ne met ça en avant — Pupelmet le fait. CISO **adore**.

### 3. TLS/SSL audit
**Inspiration** : SSL Labs Qualys.
**Pourquoi crucial** : un certificat expiré bloque les visiteurs Chrome → perte CA directe. Détection auto + alerte = ROI immédiat.

### 4. EPSS + CISA KEV
**Inspiration** : Purplemet (ils le revendiquent dans leur email avril 2025).
**Pourquoi crucial** : permet de prioriser correctement (une medium avec KEV = plus urgente qu'une critical sans). C'est la **prioritization moderne**.
- **EPSS** : score 0-1 de la probabilité d'exploitation dans les 30 jours (FIRST.org)
- **KEV** : catalogue officiel CISA des vulnérabilités activement exploitées dans le monde

### 5. Nuclei tags élargis
Au lieu de `-severity critical,high,medium` seul, on active :
- `cve` : CVE classiques
- `exposure` : fichiers leak (.env, .git, backups)
- `misconfig` : CORS, security headers
- `takeover` : subdomain takeover (= récupérer un sous-domaine désaffecté)
- `default-logins` : creds par défaut sur panels admin
- `panel` : Jenkins/Kibana/etc. exposés

---

## 🏗️ Architecture complète (Sprint 1.5)

```
Outil pupelmet/
├── pupelmet.py            ← CLI (Sprint 0)
├── pyproject.toml
├── .env
├── tools/
│   └── bin/
│       ├── subfinder.exe
│       ├── httpx.exe
│       ├── nuclei.exe
│       └── tlsx.exe       ← NEW
├── data/
│   ├── pupelmet.db        ← SQLite (schema 1.5)
│   └── cache/             ← NEW : cache EPSS + KEV (24h)
│       ├── kev_catalog.json
│       └── epss_cache.json
├── app/
│   ├── main.py            ← orchestre tout
│   ├── database.py
│   ├── models.py          ← +TlsFinding, +risk_score, +kev_count
│   ├── scanner.py         ← subfinder + httpx + résumé IA
│   ├── nuclei.py          ← +tags étendus, +vuln_priority_score
│   ├── outbound.py        ← générateur email
│   ├── dns_scan.py        ← NEW : DNS + SPF + DKIM + DMARC
│   ├── tls_scan.py        ← NEW : audit TLS via tlsx
│   ├── enrichment.py      ← NEW : EPSS + CISA KEV
│   ├── risk_score.py      ← NEW : score 0-100 + grade A-F
│   ├── templates/         ← scan.html étendu
│   └── static/css/style.css ← +Risk hero, +KEV badge, +email-sec grid
└── docs/
    ├── SPRINT_0_TUTO.md
    ├── SPRINT_1_TUTO.md
    └── SPRINT_1_5_TUTO.md ← ce fichier
```

---

## 🩺 Dépannage Sprint 1.5

| Problème | Solution |
|---|---|
| Erreur SQL "no such column kev_count" | Supprime `data/pupelmet.db` et relance |
| `tlsx.exe introuvable` | Relance `tools\install_tools.ps1` |
| DNS scan tombe en timeout | Pas grave : il continue sans DNS, retour partiel |
| EPSS API ne répond pas | Pas grave : les vulns s'affichent sans EPSS (utilisera le cache) |
| Risk Score reste à 100 | Normal si pas de Nuclei + DNS/TLS sans problème — le domaine est propre ! |
| `data\cache\kev_catalog.json` introuvable | Téléchargé au 1er scan, vérifie ta connexion |

---

## ➡️ Suite : Sprint 2

Quand Sprint 1.5 est testé/validé :
1. **Auth utilisateurs** (login email/password ou Magic link)
2. **Multi-tenant MSSP** : un revendeur gère N clients
3. **Monitoring continu** : re-scan auto chaque jour + diff = "nouveaux assets cette semaine"
4. **Export PDF** : rapport "ready to send" au client
5. **Pricing / Stripe** : Free / Starter / Pro / MSSP tiers
6. **Déploiement cloud** : pupelmet.com en ligne (Scaleway FR)
