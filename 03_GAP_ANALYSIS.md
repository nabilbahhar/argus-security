# Gap Analysis — Là où Pupelmet peut écraser le marché

> Synthèse croisée : insider knowledge (51 emails Purplemet ↔ Compucom, 28 mois) + benchmark de 11 concurrents ASM. Document décisionnel.

---

## 1. Les 4 vérités absolues du marché ASM 2026

1. **Le segment ETI/PME EU est sous-servi** : Detectify trop cher au scaling, Xpanse inaccessible (95k$ / 1000 actifs), CyCognito/Censys/Mandiant en "contact us". Aucun pricing transparent linéaire sous 50k€/an pour 1000 assets.

2. **Le produit ne suffit pas — c'est le sales enablement qui tue** : Purplemet a 100+ clients, releases mensuelles, base techno solide, et son **revendeur n°1 au Maroc envisage de rompre le contrat après 28 mois sans deal majeur**. Pas de problème technique : un problème d'activation commerciale.

3. **L'IA générative redéfinit la valeur ajoutée** : ProjectDiscovery Neo, Bishop Fox Cosmos AI, Microsoft Copilot, Tenable Hexa AI — tous bougent vers l'agentic. **Les outils qui ne génèrent QUE des findings deviennent une commodité**. Ceux qui génèrent **remediation + outbound + narrative** prennent le marché.

4. **La conformité (NIS2 / DORA / SecNumCloud) crée une obligation légale** de monitoring continu. Les CISOs ETI EU vont devoir acheter un ASM en 2026-2027 — ils chercheront un acteur européen souverain.

---

## 2. Matrice consolidée — Lacunes de chaque concurrent

| Lacune | Detectify | Defender EASM | CyCognito | Xpanse | Censys | Tenable | Bishop Fox | Mandiant | Purplemet | **Pupelmet** |
|---|---|---|---|---|---|---|---|---|---|---|
| Pricing transparent ETI | ⚠️ cher | ❌ consumption | ❌ devis | ❌ devis | ❌ devis | ❌ bundle | ❌ managed | ❌ bundle | ❌ devis | ✅ **public** |
| Time-to-value < 10 min | ⚠️ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ⚠️ | ✅ **instant** |
| Explication CVE business | ❌ | ⚠️ Copilot | ❌ | ❌ | ❌ | ⚠️ Hexa | ⚠️ humain | ⚠️ | ❌ | ✅ **GenAI native** |
| Outbound email auto (revendeur) | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ **USP unique** |
| Sales enablement / training | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ **USP unique** |
| Détection admin panels exposés | ⚠️ | ⚠️ | ✅ | ⚠️ | ❌ | ❌ | ✅ | ⚠️ | ✅ | ✅ |
| Scoring EPSS + KEV explicite | ⚠️ | ⚠️ | ✅ | ✅ | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Souveraineté UE | 🇸🇪 SE | ❌ US | ❌ US | ❌ US | ❌ US | ❌ US | ❌ US | ❌ US | 🇫🇷 FR | 🇫🇷 **FR/MA** |
| Threat intel live | ❌ | ⚠️ | ⚠️ | ⚠️ | ⚠️ | ⚠️ | ⚠️ | ✅ | ❌ | ✅ |
| API/GraphQL/serverless aware | ⚠️ | ⚠️ | ⚠️ | ❌ | ❌ | ❌ | ⚠️ | ❌ | ❌ | ✅ |
| Narratif exec hebdomadaire | ❌ | ❌ | ⚠️ | ❌ | ❌ | ❌ | ⚠️ | ❌ | ❌ | ✅ |
| Channel MSSP francophone | ❌ | ⚠️ | ❌ | ❌ | ❌ | ⚠️ | ❌ | ⚠️ | ⚠️ | ✅ **focus** |

**Lecture rapide** : Pupelmet doit gagner sur **5 axes simultanés** que personne ne fait bien :
1. Pricing transparent
2. Time-to-value instant
3. IA explicative + outbound auto
4. Sales enablement intégré
5. Souveraineté EU + canal MSSP francophone

---

## 3. Insights du terrain (emails Compucom-Purplemet) — Ce que les autres benchmarks ne diront jamais

| Insight terrain | Implication produit Pupelmet |
|---|---|
| Le revendeur ne maîtrise pas Score F / EPSS / KEV après 18 mois | **Glossaire IA contextuel + explainer in-app + simulateur de pitch** |
| Email de prospection trop dense, trop technique | **Génération auto d'email court personnalisé par secteur du prospect** |
| "X URLs détectées" est le SEUL hook qui crée la conversation | **Mettre cette métrique au cœur du dashboard + landing publique gratuite** |
| Pricing trop cher pour MENA | **Tier "Emerging Markets" avec PPP + freemium 1 domaine illimité** |
| "Personne ne suit le sujet" (Compucom) | **Portail partenaire avec pipeline, leaderboard, alertes inactivité** |
| Outils techniques mais sans soutien commercial | **AI Sales Assistant 24/7 (réponses objections, scripts, suivis)** |
| Pas de cycle 0-day rapide visible côté revendeur | **Bulletin auto "ce qui change cette semaine + qui de tes prospects est touché"** |

---

## 4. Les 5 trous qui définissent le positionnement Pupelmet

### Trou #1 — Le revendeur orphelin
Les ASM enterprise vendent en direct ou via gros intégrateurs (Sopra, Wavestone). **Personne ne fait du produit pour les MSSP/revendeurs locaux (Maroc, Afrique, MENA, Europe du Sud)**. Compucom est l'exemple type : un revendeur motivé qui galère faute d'outils d'activation.

### Trou #2 — Le CISO d'ETI sans budget enterprise
Un CISO d'une banque marocaine, d'une ETI tunisienne, d'une scale-up française à 500 employés : ne peut pas payer 95k$ Xpanse, ne veut pas devis-only CyCognito. **Il veut un prix affiché, paie par carte, démo le jour même**.

### Trou #3 — L'AppSec qui veut comprendre, pas juste détecter
ProjectDiscovery Nuclei fait des findings, mais sans contexte business. CyCognito fait du contexte business mais sans evidence chain. **Personne ne fait : "Voici la vuln. Voici pourquoi c'est P1 (EPSS 95% + KEV active). Voici la commande exacte pour patcher. Voici le ticket Jira pré-rempli."**

### Trou #4 — La régulation NIS2/DORA arrive
Les ETI EU vont être contraintes au monitoring continu d'ici fin 2026. **Aucun acteur EU souverain pure player n'est positionné pour récolter cette vague** (Detectify est SE mais raconte une histoire AppSec, pas conformité).

### Trou #5 — Le shadow AI / nouvelles surfaces
Cloudflare Workers, Vercel functions, Supabase edge, MCP servers exposés, agents IA déployés. **Aucun ASM n'a un module dédié à ces nouvelles surfaces**. C'est le marché 2027.

---

## 5. Recommandation stratégique pour Pupelmet

### Positionnement à 3 mois
> **"Le Web ASM qui se vend tout seul.**
> Pour les CISOs d'ETI EU et leurs partenaires MSSP qui veulent : *un prix clair, un onboarding instantané, des vulnérabilités traduites en risque business, et — c'est unique — la génération automatique des emails de prospection et des plans de remédiation par IA."*

### Cibles primaires
1. **MSSP / revendeurs francophones** (Maroc, Tunisie, Sénégal, Belgique, Suisse, France) — segment Purplemet a raté
2. **ETI françaises secteur régulé** (banque mutualiste, mutuelle santé, ETI industrielle) — driver NIS2
3. **DSI universités/secteur public MA et FR** — Nabil a déjà 14 scans prêts à monétiser

### Cibles secondaires (phase 2)
4. AppSec teams scale-ups EU
5. Bug bounty / red team (offre OSS gratuite pour adoption viral)

### Ce qu'on NE FAIT PAS
- Pas de Fortune 500 globaux (déjà capturés)
- Pas de scan IPv4 internet-wide (Censys / Xpanse dominent)
- Pas de managed pentest humain (Bishop Fox)
- Pas de bundling avec SIEM/XDR (Microsoft / Palo Alto / Google)
- Pas de templates community contributors (ProjectDiscovery Nuclei domine)

---

*Document à valider avant écriture du positionnement final (04_USP_POSITIONING.md) et de l'architecture (05_ARCHITECTURE.md).*
