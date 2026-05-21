# Sprint 0 — Tutoriel pas-à-pas

> Construis et lance ton **mini-Pupelmet** en 1 weekend. Chaque terme technique est traduit avec un exemple ASM concret.

---

## 🎯 Objectif

À la fin de ce tuto, tu sauras :
1. Faire fonctionner Python et installer ses outils sur Windows
2. Comprendre ce que fait chaque ligne de `pupelmet.py`
3. Lancer un scan complet sur n'importe quel domaine
4. Sauver les résultats en JSON pour les analyser plus tard

**Temps estimé** : 4-6h sur 1 weekend.

---

## 🧱 Étape 1 — Vérifier que Python est installé

**Python** *(= un langage de programmation, comme l'anglais ou le français mais pour parler à un ordinateur. On l'utilise dans 80% des projets de cybersécurité.)*

Ouvre **PowerShell** *(= la fenêtre noire de Windows pour taper des commandes système. Touche Windows → tape "powershell" → Entrée.)*

Tape :

```powershell
python --version
```

Tu devrais voir : `Python 3.14.3` (ou similaire). **Si oui, passe à l'étape 2.**

**Si "command not found"** ou erreur :
1. Va sur https://www.python.org/downloads/
2. Télécharge Python 3.12+ pour Windows
3. **IMPORTANT** : à l'installation, coche **"Add Python to PATH"** *(= dit à Windows où trouver Python pour pouvoir le lancer depuis n'importe où.)*
4. Redémarre PowerShell et retape `python --version`

---

## 🧱 Étape 2 — Installer `uv` (manager de paquets Python)

**uv** *(= un outil moderne qui installe les bibliothèques Python 10-100× plus vite que `pip`. Imagine `pip` comme un colis classique La Poste, et `uv` comme une livraison Amazon Prime.)*

```powershell
pip install uv
```

Test :
```powershell
uv --version
```

Tu devrais voir : `uv 0.x.x`.

---

## 🧱 Étape 3 — Aller dans le dossier du projet

```powershell
cd "C:\Users\NABIL BAHHAR\Projets Cyber\Outil pupelmet"
```

**cd** *(= "change directory" — change de dossier. Comme double-cliquer sur un dossier dans l'explorateur, mais en ligne de commande.)*

Vérifie que tu es au bon endroit :
```powershell
ls
```

Tu dois voir : `pupelmet.py`, `pyproject.toml`, `tools/`, `docs/`, `scans/`, etc.

---

## 🧱 Étape 4 — Installer les dépendances Python du projet

**Dépendances** *(= les librairies externes dont notre script a besoin. Ex: pour parler à Claude IA, on utilise la lib `anthropic`. On n'écrit pas tout from scratch — on s'appuie sur du code que d'autres ont déjà écrit.)*

```powershell
uv sync
```

Ce que ça fait :
1. Lit `pyproject.toml`
2. Voit qu'on a besoin de `anthropic`, `httpx`, `python-dotenv`, `rich`
3. Crée un **environnement virtuel** *(= une "boîte isolée" pour les libs de CE projet, sans polluer le reste de ton système Python)* dans le dossier `.venv/`
4. Télécharge et installe les libs dans cette boîte

Tu vois plein de lignes du style `+ anthropic==0.40.x`, `+ rich==13.x.x`. C'est normal.

**Test** que tout est OK :
```powershell
uv run python -c "import anthropic; print('OK')"
```

Tu dois voir `OK`.

> 💡 **Note** : `uv run` exécute Python depuis l'environnement virtuel (`.venv`). Si tu utilises juste `python` directement, Windows utilise le Python global qui ne connaît pas nos libs. **Toujours préfixer par `uv run` ou activer l'env virtuel** (cf. astuce en bas).

---

## 🧱 Étape 5 — Télécharger les outils OSS (subfinder + httpx)

**OSS** *(= Open Source Software. Du code gratuit, public, utilisable par n'importe qui. Subfinder et httpx sont devenus des standards de fait dans la communauté cybersé.)*

```powershell
powershell -ExecutionPolicy Bypass -File .\tools\install_tools.ps1
```

*(Le flag `-ExecutionPolicy Bypass` autorise l'exécution de scripts PowerShell non signés — c'est sûr ici puisque c'est notre propre script.)*

Le script va :
1. Télécharger `subfinder.zip` depuis github.com/projectdiscovery/subfinder
2. Télécharger `httpx.zip` depuis github.com/projectdiscovery/httpx
3. Les décompresser dans `tools/bin/`

Test :
```powershell
.\tools\bin\subfinder.exe -version
.\tools\bin\httpx.exe -version
```

Tu devrais voir leurs numéros de version respectifs.

**⚠️ Si Windows Defender bloque** : c'est normal pour des binaires Go non signés. Solution :
1. Va dans **Sécurité Windows → Protection contre les virus → Paramètres**
2. Ajoute une exclusion sur le dossier `tools/bin/`

---

## 🧱 Étape 6 — Configurer la clé API Claude

**API Claude** *(= le service IA d'Anthropic. On envoie du texte, Claude répond du texte. Chaque requête coûte quelques centimes. C'est ce qui va générer les résumés et plus tard les emails de prospection automatiques.)*

1. Va sur **https://console.anthropic.com/**
2. Connecte-toi (ou crée un compte si pas déjà fait)
3. Va dans **API Keys** → clique **"Create Key"**
4. Copie la clé (commence par `sk-ant-...`)

Crée ton fichier `.env` *(= "environment" — un fichier qui stocke des secrets en dehors du code, jamais committé sur GitHub)* :

```powershell
copy .env.example .env
```

Ouvre `.env` avec Notepad :
```powershell
notepad .env
```

Remplace `sk-ant-...` par ta vraie clé. Sauvegarde.

> 🔒 **Sécurité** : le fichier `.env` est dans `.gitignore` — Git l'ignore et ne le partagera JAMAIS. Si tu pushes ton code sur GitHub, ta clé reste sur ta machine.

---

## 🧱 Étape 7 — LE GRAND MOMENT 🎉

Lance ton premier scan :

```powershell
uv run python pupelmet.py compucom.ma
```

Tu vas voir, dans l'ordre :
1. ⏳ **"Découverte des sous-domaines..."** *(subfinder cherche dans 30+ sources OSINT)*
2. ⏳ **"Test HTTP + détection techno..."** *(httpx frappe à la porte de chacun)*
3. ⏳ **"Génération du résumé IA..."** *(Claude rédige le brief)*
4. 📊 **Un tableau coloré** avec toutes les URLs trouvées
5. 🤖 **Un résumé en français** dans un encadré bleu
6. 💾 **"Résultats sauvegardés → scans/compucom.ma_2026-...json"**

**Tu viens de faire en 30 secondes ce que Benjamin Krown faisait à la main en 15 minutes.**

---

## 🧱 Étape 8 — Tester sur les domaines des emails Purplemet

Pour mesurer l'écart entre Pupelmet et Purplemet, lance sur les mêmes domaines :

```powershell
uv run python pupelmet.py uae.ma         # 871 webapps selon Purplemet (avril 2025)
uv run python pupelmet.py um6p.ma        # 174 webapps selon Purplemet (février 2024)
uv run python pupelmet.py usmba.ac.ma    # 238 webapps selon Purplemet
uv run python pupelmet.py avito.ma       # 128 webapps selon Purplemet
uv run python pupelmet.py purplemet.com  # savoure l'ironie
```

Compare le nombre trouvé avec celui que Purplemet annonçait. Tu seras peut-être en dessous (Purplemet a plus de sources OSINT premium) mais l'ordre de grandeur sera là.

---

## 🛠️ Astuce — Activer l'environnement virtuel une fois pour toutes

Au lieu de retaper `uv run` à chaque commande :

```powershell
.\.venv\Scripts\Activate.ps1
```

Tu vois `(pupelmet)` apparaître devant ton prompt → tu es dans l'env. Maintenant tu peux directement taper :
```powershell
python pupelmet.py compucom.ma
```

Pour sortir : `deactivate`.

---

## 🩺 Dépannage rapide

| Problème | Solution |
|---|---|
| `'uv' is not recognized` | Ré-exécute `pip install uv` puis redémarre PowerShell |
| `subfinder.exe introuvable` | Re-lance `tools/install_tools.ps1` |
| `ANTHROPIC_API_KEY manquante` | Vérifie que `.env` existe avec ta vraie clé (pas le placeholder) |
| `RateLimitError` sur Claude | Ta clé n'a plus de crédit → ajoute du crédit sur console.anthropic.com |
| 0 sous-domaine trouvé | Soit le domaine n'a vraiment qu'un seul actif, soit teste avec `-v` pour debug |
| ExecutionPolicy bloque le script | Lance avec `-ExecutionPolicy Bypass` (voir Étape 5) |
| Windows Defender supprime un .exe | Ajoute `tools/bin/` aux exclusions Defender |

---

## 🧠 Ce que tu as appris ce weekend

- ✅ Installer Python + uv sur Windows
- ✅ Cloner et installer un projet Python (`uv sync`)
- ✅ Variables d'environnement et fichier `.env` (= protéger les secrets)
- ✅ Lancer un script externe depuis Python (`subprocess`)
- ✅ Appeler une API REST via SDK (`anthropic` → Claude)
- ✅ Manipuler du JSON
- ✅ Afficher proprement dans un terminal (`rich`)
- ✅ Le pipeline ASM de base : **découverte → probing → fingerprinting → résumé**

**Tu as construit un MVP fonctionnel qui réplique 60% de ce que Purplemet vend.** Les 40% restants (scoring CVE, monitoring continu, outbound auto, dashboard web) viennent dans les Sprints suivants.

---

## ➡️ Suite : Sprint 1

Une fois Sprint 0 testé et validé, on passe à **Sprint 1** qui ajoutera :
1. **Module Nuclei** = vrai scanner de vulnérabilités CVE avec scoring EPSS+KEV
2. **Module IA outbound** = à partir d'un scan, génère l'email de prospection (ton USP unique)
3. **Mini-interface web** = une page HTML pour la démo sans le terminal

Dis-moi quand tu es prêt.
