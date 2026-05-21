# Architecture & Stack — Pupelmet MVP

> Décisions techniques pour livrer le MVP en 6-8 semaines. Pragmatique, modulaire, scalable, hébergé EU.

---

## 🏗️ Vue d'ensemble

```
┌─────────────────────────────────────────────────────────────┐
│  FRONTEND (Next.js sur Vercel EU)                          │
│  ├─ Landing publique (démo gratuite)                       │
│  ├─ Dashboard (scan + findings + outbound)                 │
│  └─ Portail MSSP (multi-tenant)                            │
└─────────────────────────────────────────────────────────────┘
                            ↓ HTTPS
┌─────────────────────────────────────────────────────────────┐
│  BACKEND API (FastAPI Python sur Scaleway FR)              │
│  ├─ Auth (Supabase Auth)                                   │
│  ├─ Scan orchestration (BullMQ → workers)                  │
│  ├─ Findings storage (Postgres)                            │
│  └─ AI services (Claude API)                               │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│  WORKERS (Python sur Scaleway FR)                          │
│  ├─ Discovery worker (subfinder, httpx, dnsx)              │
│  ├─ Fingerprinting worker (Nuclei + custom)                │
│  ├─ Vuln scanning worker (Nuclei templates + CVE/EPSS/KEV) │
│  └─ AI worker (Claude — explain + outbound + remediation)  │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│  DATA LAYER (Supabase EU — Postgres + Storage + Realtime)  │
│  ├─ Domains, Assets, Findings, Scans                        │
│  ├─ Users, Orgs, MSSP relationships                         │
│  └─ CVE/EPSS/KEV cache (refreshed quotidien)               │
└─────────────────────────────────────────────────────────────┘
```

---

## 🛠️ Stack technique — décisions

### Frontend
- **Next.js 15** (App Router) — SEO landing + dashboard SSR
- **React 19** + **TypeScript**
- **Tailwind 4** + **shadcn/ui** — UI rapide, dark mode native
- **TanStack Query** — fetch/cache
- **Recharts** — graphes findings
- **Hébergement** : Vercel EU (Frankfurt) ou OVH

### Backend
- **FastAPI** (Python 3.12) — API REST + WebSocket
- **Pydantic v2** — validation/serialization
- **SQLAlchemy 2 async** — ORM
- **BullMQ-Python** (ou **Celery + Redis**) — job queue
- **Hébergement** : Scaleway FR (souverain) ou OVH

### Workers (scan engines)
- **Python orchestrator** qui appelle des outils OSS battle-tested :
  - **subfinder** (ProjectDiscovery) — subdomain enum passive
  - **dnsx** — DNS resolution
  - **httpx** — HTTP probing + tech detection
  - **nuclei** — vuln scanning avec 12k+ templates
  - **wappalyzer-cli** (ou cli node) — tech fingerprinting
- **Custom Python modules** pour :
  - Détection admin panels (regex sur paths courants)
  - SSL/TLS analysis (sslyze)
  - CVE matching (mapping techno → CVE via NVD API)
- **Pas de scan agressif** : mode passif par défaut, actif opt-in

### Base de données
- **Supabase** (Postgres managed EU) — auth + DB + storage + realtime + row-level security
- Alternatif : **Postgres self-hosted sur Scaleway** si on veut full souveraineté

### Intelligence
- **Claude Sonnet 4.6** (API Anthropic) pour :
  - Explainer : finding → langage business
  - Outbound generator : findings → email/LinkedIn/script
  - Remediation : finding → commande/PR/playbook
  - Exec narrative : scans hebdo → résumé CISO
- **Prompts cachés** via prompt caching Anthropic (réduction coût)
- **Garde-fous** : tous les LLM outputs validés contre schémas Pydantic

### Data externe
- **NVD API** (CVE) — cache local refresh quotidien
- **FIRST EPSS API** — scores quotidiens
- **CISA KEV catalog** — JSON officiel
- **Crt.sh** (Certificate Transparency) — découverte passive
- **VirusTotal API** (free tier) — IP reputation

### Observability
- **Sentry** (EU region) — erreurs
- **PostHog EU** — analytics produit + replay
- **Better Stack** — logs + uptime

### CI/CD & infra
- **GitHub** repo privé
- **GitHub Actions** — tests + build + deploy
- **Docker** + **docker-compose** local
- **Terraform** pour infra cloud (opt phase 2)

### Pricing & paiement
- **Stripe** (Stripe Tax pour TVA EU/MENA) — billing public
- **Webhooks Stripe → Supabase** pour droits

---

## 📦 Modules du MVP (par ordre de priorité)

### Module 1 — Discovery Engine (semaine 1-2)
**Input** : domaine (ex: `compucom.ma`)
**Output** : liste d'actifs (sous-domaines, IPs, certs, technos)
**Stack** : subfinder + dnsx + httpx + wappalyzer
**Tests** : doit retrouver 80%+ des sous-domaines connus de `compucom.ma`

### Module 2 — Vuln Scanner (semaine 2-3)
**Input** : liste d'actifs du module 1
**Output** : findings (CVE, SSL, admin panels, debug pages, EOL)
**Stack** : nuclei + custom checks + sslyze
**Scoring** : CVSS + EPSS + KEV → score Pupelmet unique (0-100)

### Module 3 — Explainer IA (semaine 3-4)
**Input** : finding brut technique
**Output** : explication business + impact + recommandation
**Stack** : Claude Sonnet 4.6 + prompts cachés + Pydantic
**Test** : un dirigeant non-tech doit comprendre en 30 secondes

### Module 4 — Outbound Generator (semaine 4-5) — **USP UNIQUE**
**Input** : scan complet + secteur du prospect (déduit du domaine)
**Output** :
- 1 email court (3 paragraphes max)
- 1 message LinkedIn (250 char max)
- 1 PDF 1-pager
- 10 réponses aux objections types
**Stack** : Claude Sonnet 4.6 + WeasyPrint (PDF) + templates Jinja2

### Module 5 — Dashboard Web (semaine 5-6)
- Vue domaine (overview + findings + technos + tendances)
- Vue scan (history + diff)
- Vue outbound (générer + éditer + envoyer)
- Vue settings (utilisateurs + facturation + intégrations)

### Module 6 — Landing publique + démo gratuite (semaine 6-7)
- Site marketing SEO
- Démo interactive (entrée d'un domaine → résultat live)
- Pricing public
- Signup self-serve avec Stripe

### Module 7 — Portail MSSP (semaine 7-8)
- Multi-tenant (un MSSP gère N clients)
- White-label basique (logo + couleurs)
- Pipeline tracker simple

### Modules phase 2 (mois 3+)
- Monitoring continu + alertes temps réel
- Exec narratives auto (rapport hebdo)
- API REST pour intégrations
- Modules Cloud (AWS misconfigs)
- Modules Shadow AI (MCP, Vercel, Supabase)

---

## 🔒 Sécurité & conformité (dès le MVP)

- **HTTPS partout** (Let's Encrypt + HSTS)
- **Row-level security** Supabase (les MSSPs ne voient pas les données des autres)
- **Secrets vault** : Doppler ou Infisical
- **Pas de stockage de PII inutile** (minimum strict)
- **Logs anonymisés** (pas de payloads de findings dans Sentry)
- **Hébergement EU only** dès le départ
- **Audit logs** sur toutes les actions critiques
- **DPA** prêt pour clients RGPD
- **Pages /security et /privacy** sur landing dès le lancement

---

## 💰 Coûts estimés MVP (mensuel, 6-8 semaines de dev)

| Poste | Coût | Notes |
|---|---|---|
| Scaleway (API + workers) | 50-150 € | 2-3 VMs |
| Supabase Pro EU | 25 € | DB + auth + storage |
| Vercel Pro | 20 € | Frontend hosting |
| Claude API (Sonnet 4.6) | 50-300 € | Selon volume scans |
| Sentry + PostHog + BetterStack | 50 € | Free tiers possibles au début |
| Stripe | 0 € | % par transaction |
| Domaine + emails | 15 € | OVH |
| **Total mensuel infra** | **~210-560 €** | Scalable |
| **Coût dev** (toi + moi en pair) | **0 € si auto-fait** | Sinon devis |

---

## 🚀 Plan d'exécution sur 8 semaines

```
Semaine 1  │ Setup repo + infra + auth + Discovery Engine
Semaine 2  │ Discovery Engine fin + Vuln Scanner début
Semaine 3  │ Vuln Scanner fin + Explainer IA début
Semaine 4  │ Explainer IA fin + Outbound Generator début
Semaine 5  │ Outbound Generator fin + Dashboard début
Semaine 6  │ Dashboard fin + Landing publique début
Semaine 7  │ Landing fin + Portail MSSP début
Semaine 8  │ Portail MSSP fin + Beta tests avec 3 utilisateurs
```

---

## 🎯 Critères de succès du MVP

À 8 semaines, on doit pouvoir :
- ✅ Scanner un domaine en moins de 90 secondes
- ✅ Générer un email de prospection convaincant pour ce domaine
- ✅ Vendre via une landing publique avec carte bancaire
- ✅ Inviter 3 MSSPs francophones à tester gratuitement
- ✅ Avoir au moins 1 conversion payante (même Free → Starter)

---

## 📍 Décisions encore ouvertes (à trancher avant code)

1. **Langage backend** : Python (FastAPI) recommandé ✅ vs Node.js (Hono/Express). **Reco : Python** car écosystème security plus riche (sslyze, scapy, etc.) et IA-friendly.
2. **Auth** : Supabase Auth (rapide) vs Clerk (premium UX) vs roll-our-own. **Reco : Supabase**.
3. **Job queue** : Celery (Python natif) vs BullMQ (TS) vs Redis Streams. **Reco : Celery** (cohérent stack Python).
4. **CDN/Hosting frontend** : Vercel EU vs Cloudflare Pages EU. **Reco : Vercel** (Next.js natif).
5. **Open source ?** : core scanner OSS sous AGPLv3 + offre SaaS payante (modèle ProjectDiscovery). **Reco : oui phase 2, pas tout de suite.**

---

*Document à valider avant lancement de l'implémentation. Étape suivante : init repo + structure code.*
