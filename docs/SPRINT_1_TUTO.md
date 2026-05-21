# Sprint 1 — Pupelmet web app (UI hacking dark + persistance)

> Tu passes du script CLI à une **vraie app web** qui sauvegarde tout, scanne avec Nuclei (CVE), et génère des emails de prospection automatiques.

---

## 🎯 Ce qui est nouveau vs Sprint 0

| Fonctionnalité | Sprint 0 | Sprint 1 |
|---|---|---|
| Interface | Terminal | **Web (FastAPI)** avec UI hacking dark |
| Persistance | JSON par scan | **SQLite** — tous les scans en mémoire, consultables à tout moment |
| Scan CVE | ❌ | ✅ **Nuclei** (12k+ templates) |
| Email outbound IA | ❌ | ✅ **Générateur d'email + LinkedIn + 5 objections** |
| Historique | Manuel | ✅ Page dédiée avec tous les scans |
| Re-scan | Re-lancer commande | ✅ Bouton, et tout reste comparable |

---

## 🧱 Pré-requis

Sprint 0 doit être fait (`uv sync` + outils OSS installés + `.env` configuré).
Si pas le cas, retourne à [`SPRINT_0_TUTO.md`](SPRINT_0_TUTO.md).

---

## 🧱 Étape 1 — Mettre à jour les dépendances Python

Sprint 1 ajoute FastAPI, SQLAlchemy, Jinja2 (= moteur de templates HTML pour Python).

```powershell
cd "C:\Users\NABIL BAHHAR\Projets Cyber\Outil pupelmet"
python -m uv sync
```

Tu verras `+ fastapi`, `+ uvicorn`, `+ sqlalchemy`, `+ jinja2`. C'est bon.

---

## 🧱 Étape 2 — Télécharger Nuclei

```powershell
powershell -ExecutionPolicy Bypass -File .\tools\install_tools.ps1
```

Le script va :
1. Voir que subfinder + httpx sont déjà installés → skip
2. Télécharger **nuclei.exe** (~50 Mo)
3. **Télécharger les 12 000+ templates CVE** dans `%USERPROFILE%\nuclei-templates\` (~150 Mo, première fois seulement, ~2 min)

*(Un "template Nuclei" = un fichier YAML qui décrit comment détecter UNE vulnérabilité. Ex: `panel-jenkins.yaml` détecte une instance Jenkins exposée. La communauté en maintient 12 000+ couvrant la plupart des CVEs publiques.)*

Test :
```powershell
.\tools\bin\nuclei.exe -version
```

---

## 🧱 Étape 3 — Lancer l'app web

```powershell
python -m uv run uvicorn app.main:app --reload
```

*(`uvicorn` = le "serveur" qui exécute notre FastAPI app et reçoit les requêtes du navigateur. `--reload` = recharge automatiquement quand on modifie le code.)*

Tu vois :
```
INFO:     Uvicorn running on http://127.0.0.1:8000
INFO:     Application startup complete.
```

**Ouvre ton navigateur sur** :
```
http://127.0.0.1:8000
```

🎉 Tu vois la **landing page Pupelmet** : titre néon vert/cyan/violet, un input pour le domaine, un bouton SCAN.

---

## 🧱 Étape 4 — Lancer ton premier scan via le web

1. Dans l'input, tape un domaine : `compucom.ma`
2. (Optionnel) Coche **"Activer Nuclei"** pour un scan CVE complet (+5-15 min de temps)
3. Clique **► SCAN**

Tu arrives sur la **page du scan** (`/scan/1`) :
- Au début : status "running" + spinner néon clignotant "⟳ SCAN EN COURS..."
- La page se rafraîchit automatiquement toutes les 2 secondes (polling JS)
- Les stats (Actifs / Vivants / Vulns / Critical / High) se mettent à jour en live

Quand fini (~30s sans Nuclei, ~5-15min avec) :
- ✅ Badge passe à **"completed"**
- 📊 **Tableau des actifs** apparaît
- ⚠️ Si Nuclei activé : **tableau des vulnérabilités** classé par sévérité
- 🤖 **Brief exécutif Claude IA** s'affiche dans un encadré violet
- 📧 **Bouton "Générer email"** pour le pitch outbound

---

## 🧱 Étape 5 — Générer un email de prospection (USP UNIQUE)

Sur la page du scan terminé, en bas :

1. Choisis un style :
   - **court** : email 3 paragraphes (recommandé)
   - **long** : email 5-6 paragraphes
   - **formel** : vouvoiement strict, signature corporate
   - **direct** : ton disruptif fondateur tech
2. Clique **► Générer**

Tu obtiens :
- **Objet** : ligne d'accroche < 70 caractères
- **Corps de l'email** : texte prêt à copier dans Outlook
- **Message LinkedIn** : version < 250 caractères
- **5 réponses aux objections** ("On a déjà Nessus", "C'est trop cher", etc.)

C'est ce que tu demandais à Benjamin Krown par email en avril 2025 :
> *"Peux-tu me préparer un mail par Domain ?"*

Tu n'as plus besoin de lui — Pupelmet le fait en 5 secondes.

---

## 🧱 Étape 6 — Consulter l'historique

Clique **"Historique"** dans la nav en haut → `/history`

Tu vois **tous tes scans passés** :
- Domaine, status, actifs, vulnérabilités, date, durée
- Bouton **"Voir"** → rouvre la page complète du scan
- Bouton **"✕"** → supprime le scan (avec confirmation)

**Toutes ces données sont stockées dans** `data/pupelmet.db` (= fichier SQLite local). Tu peux le copier sur un autre PC, le sauvegarder, ou même l'ouvrir avec [SQLite Browser](https://sqlitebrowser.org/) pour voir les tables brutes.

---

## 🛠️ Architecture (pour comprendre)

```
Outil pupelmet/
├── pupelmet.py            ← le CLI (Sprint 0, marche toujours)
├── pyproject.toml         ← dépendances du projet
├── .env                   ← ta clé API Claude (secret)
├── tools/
│   ├── install_tools.ps1
│   └── bin/
│       ├── subfinder.exe
│       ├── httpx.exe
│       └── nuclei.exe     ← NOUVEAU Sprint 1
├── data/
│   └── pupelmet.db        ← NOUVEAU Sprint 1 : ta DB SQLite
├── app/                   ← NOUVEAU Sprint 1 : l'app web
│   ├── main.py            ← FastAPI : routes + tâches de fond
│   ├── database.py        ← config SQLite + sessions
│   ├── models.py          ← tables (Scan, Asset, Vuln, OutboundEmail)
│   ├── scanner.py         ← module subfinder + httpx + résumé IA
│   ├── nuclei.py          ← module scan CVE
│   ├── outbound.py        ← générateur email/LinkedIn/objections
│   ├── templates/         ← HTML (Jinja2)
│   │   ├── base.html      ← layout commun (header, footer, CSS)
│   │   ├── index.html     ← landing page + form scan
│   │   ├── scan.html      ← page d'un scan (résultats)
│   │   └── history.html   ← tableau de tous les scans
│   └── static/
│       └── css/style.css  ← design hacking dark néon
├── scans/                 ← anciens JSON du Sprint 0 (non utilisés ici)
└── docs/
    ├── SPRINT_0_TUTO.md
    └── SPRINT_1_TUTO.md   ← ce fichier
```

**Termes nouveaux** :
- **FastAPI** *(= framework web Python moderne, comme Express en Node.js. Définit des routes : "quand quelqu'un va sur /scan, exécute cette fonction".)*
- **Uvicorn** *(= le "moteur" qui fait tourner FastAPI. Reçoit les requêtes HTTP du navigateur et les transmet à FastAPI.)*
- **Jinja2** *(= moteur de templates HTML. Permet d'écrire du HTML avec des variables `{{ scan.domain }}` et des conditions `{% if ... %}`.)*
- **SQLAlchemy ORM** *(= mapping objet-relationnel. On manipule des objets Python `scan.assets_count` au lieu d'écrire du SQL `SELECT assets_count FROM scans WHERE ...`.)*
- **SQLite** *(= base de données dans UN seul fichier. Zéro install, zéro serveur, idéal pour un MVP local.)*
- **Background task** *(= tâche qui tourne en arrière-plan. Le scan prend 30s+ donc on ne fait pas attendre l'utilisateur sur la page : on lance le scan en background et on poll pour voir où il en est.)*
- **Polling** *(= rafraîchir périodiquement. Toutes les 2 sec, le JS demande au serveur "où en est le scan ?" et met à jour l'UI.)*

---

## 🩺 Dépannage rapide

| Problème | Solution |
|---|---|
| `ModuleNotFoundError: No module named 'fastapi'` | Relance `python -m uv sync` |
| Port 8000 déjà utilisé | Lance avec `--port 8001` : `uvicorn app.main:app --reload --port 8001` |
| Nuclei prend très longtemps | Normal sur un gros domaine. Désactive le checkbox "Activer Nuclei" pour scans rapides. |
| `nuclei.exe` introuvable | Re-lance `tools\install_tools.ps1` |
| Le scan reste en "running" indéfiniment | Regarde le terminal où tourne uvicorn — l'erreur sera visible |
| Le design ne se charge pas | Hard-refresh : Ctrl+F5 |
| Caractères bizarres dans la DB | SQLite est en UTF-8, c'est juste l'affichage console qui galère |

---

## 🎯 Critères de succès Sprint 1

À la fin de ce sprint, tu dois pouvoir :

- ✅ Lancer `uvicorn app.main:app --reload` sans erreur
- ✅ Voir la landing Pupelmet sur http://127.0.0.1:8000
- ✅ Scanner `compucom.ma` via le formulaire web
- ✅ Voir le résultat avec stats, résumé IA, tableau d'actifs
- ✅ Activer Nuclei et voir des vulnérabilités
- ✅ Générer un email outbound + LinkedIn + objections
- ✅ Aller dans Historique et retrouver tes anciens scans
- ✅ Supprimer un scan
- ✅ Comprendre la structure du projet (qui fait quoi)

---

## ➡️ Suite : Sprint 2

Une fois Sprint 1 testé :
1. **Multi-tenant** : portail MSSP (un revendeur gère plusieurs clients)
2. **Monitoring continu** : re-scan automatique chaque jour + diff (= changements)
3. **Auth** : login utilisateurs (Supabase Auth ou simple email/password)
4. **Pricing / Stripe** : tier Free / Starter / Pro / MSSP
5. **Déploiement** : pour passer de localhost à pupelmet.com en ligne
