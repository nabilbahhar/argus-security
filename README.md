# ARGUS Security

> SaaS de Web Attack Surface Management par **Exasys**.
> Cartographie les actifs web exposés d'un domaine, identifie les vulnérabilités
> et délivre un rapport exécutif clair pour les dirigeants de PME, sans jargon.

---

## Status

- ✅ **Sprint 0** : CLI Python (script tout-en-un)
- ✅ **Sprint 1** : Web app FastAPI + UI duale (hacking + marketing)
- ✅ **Sprint 1.5** : Risk Score A-F, sécurité email (SPF/DKIM/DMARC), TLS, EPSS+KEV
- ✅ **Sprint 2 — auth & billing** : comptes utilisateurs, vérif email obligatoire, reset password, dropdown user, settings, Stripe Checkout
- ✅ **Sprint 3 — branding** : rebrand complet ARGUS by Exasys, suppression mentions de localisation
- 🔜 **Sprint 4** : déploiement prod (VPS, DNS, HTTPS), WhatsApp notifications (Twilio)

---

## Stack technique

| Couche | Technologies |
|---|---|
| Backend | FastAPI 0.115+, SQLAlchemy 2, Starlette SessionMiddleware |
| DB | SQLite (dev) — migration vers PostgreSQL possible en prod |
| Frontend | Jinja2 templates + CSS custom (dual theme) |
| Pipeline scan | Binaires Go via subprocess : subfinder, httpx, nuclei, naabu, ffuf, katana, tlsx, dnsx |
| Enrichment vuln | EPSS (FIRST.org) + CISA KEV |
| LLM (briefs) | Anthropic Claude API |
| PDF | fpdf2 (pure Python) |
| Billing | Stripe Checkout (subscription mode) + webhook |
| Email | SMTP générique (Resend / Postmark / Gmail / etc.) |
| Avatar | Cropper.js (CDN) + base64 dans DB |

---

## Setup local

```powershell
# 1. Cloner
git clone <repo-url>
cd "Outil pupelmet"

# 2. Installer les deps Python
uv sync

# 3. Variables d'env
copy .env.example .env
# → remplir au minimum : ANTHROPIC_API_KEY, SESSION_SECRET, ADMIN_EMAIL

# 4. Télécharger les binaires de scan
.\tools\install_tools.ps1

# 5. Lancer le serveur
.venv\Scripts\uvicorn app.main:app --reload --reload-dir app
```

Accès : http://localhost:8000

Le premier compte créé avec l'email `ADMIN_EMAIL` devient **automatiquement admin**.

---

## Fonctionnalités

### Pour les utilisateurs
- Scan d'un domaine en 60 secondes (depuis l'accueil)
- Vérification email obligatoire à l'inscription (token 24h)
- Reset mot de passe par email (token 1h, anti-enumeration)
- 4 plans : Free / Essentiel (29€) / Pro (79€) / Agency (249€)
- **Paywall 20%** : free voit un échantillon, payant voit tout
- Mode pentest avec double consentement horodaté (Pro+)
- Score de risque A-F (Mozilla Observatory-like)
- Brief exécutif clair généré par LLM (anti-jargon)
- Export PDF du rapport (Essentiel+)
- Photo de profil avec crop circulaire (Cropper.js)
- Paiement carte via Stripe Checkout
- Notifications WhatsApp (opt-in, à brancher)

### Pour l'admin (`/admin`)
- KPIs : utilisateurs, scans, MRR estimé, repartition par plan
- Top domaines scannés (avec dernier grade + owner)
- Liste utilisateurs avec change-plan inline
- Liste des leads WhatsApp opt-in
- Historique de tous les scans
- Recherche live (filtre client-side)

---

## Sécurité

- Bcrypt rounds=12 pour les password hashes
- Sessions signées (`itsdangerous`), `https_only` configurable
- `SESSION_SECRET` requis en production (crash si manquant + `DEBUG=0`)
- Rate limit `/login` : 8 tentatives / 5 min par IP+email
- Rate limit `/forgot-password` : 3 demandes / 10 min par IP
- Tokens uniques (64 chars urlsafe) avec expiration et usage unique
- Validation stricte des inputs : regex domaine, email (RFC light), téléphone international
- Anti-enumeration sur les flows forgot-password
- Aucune mention d'outils internes ou de localisation dans le contenu user-facing
- Audit pentest avec consentement légal horodaté en DB
- Prompts LLM verrouillés : interdiction d'auto-mention IA/Claude/outils/localisation

---

## Structure du projet

```
app/
├── main.py                    # Routes FastAPI + middleware + helpers
├── database.py                # SQLAlchemy session/engine
├── models.py                  # User, Scan, Asset, Vuln, Token...
├── auth.py                    # hash/verify password, get_current_user, plan helpers
├── email_sender.py            # SMTP générique + templates (welcome, reset, verify, plan)
├── pdf_report.py              # Génération PDF rapport (fpdf2)
├── scanner.py                 # Pipeline scan principal + appel LLM
├── discovery.py               # Sources OSINT (multi-sources combinées)
├── nuclei.py                  # Wrapper scan CVE
├── dns_scan.py                # DNS + SPF/DKIM/DMARC
├── tls_scan.py                # TLS/SSL audit
├── enrichment.py              # EPSS + CISA KEV (cache 24h)
├── risk_score.py              # ARGUS Risk Score 0-100 → A-F
├── pentest.py                 # Mode pentest actif (naabu/ffuf/katana)
├── templates/                 # Jinja2 HTML
└── static/css/style.css       # CSS unique (dual theme via body.marketing)

tools/
├── bin/                       # Binaires Go (ignored)
└── install_tools.ps1          # Download script

data/                          # SQLite + cache (ignored)
logs/                          # Logs uvicorn + previews emails dev (ignored)
```

---

## Variables d'environnement

Voir [`.env.example`](.env.example).

Minimum pour démarrer :
- `ANTHROPIC_API_KEY` : pour le brief LLM
- `SESSION_SECRET` : générer avec `python -c "import secrets; print(secrets.token_urlsafe(48))"`
- `ADMIN_EMAIL` : email du compte qui sera admin

Pour Stripe (paiement carte) :
- `STRIPE_SECRET_KEY`, `STRIPE_PRICE_ESSENTIEL`, `STRIPE_PRICE_PRO`, `STRIPE_PRICE_AGENCY`

Pour les emails en prod :
- `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`, `SMTP_FROM_EMAIL`

Sans SMTP, les emails sont écrits dans `logs/emails/*.html` pour preview.

---

## Branding

ARGUS Security est une **marque d'Exasys**, société de cybersécurité créée en 2015.

Le projet utilise une palette CSS duale :
- Pages **scan** → thème "terminal" (JetBrains Mono, fond sombre, accents néon cyan/violet/vert)
- Pages **marketing / auth / settings** → thème "SaaS moderne" (Inter, espacements généreux, gradient bleu→violet)

Le switch est fait via `<body class="marketing">` sur les pages qui héritent.

---

## License

© Exasys. Tous droits réservés.
