# Benchmark concurrentiel - Web Attack Surface Management (ASM)

> Recherche menee pour positionner Pupelmet face aux 11 acteurs cles du marche EASM/ASM en 2025-2026.
> Sources : sites editeurs, Gartner Peer Insights, G2, GigaOm Radar 2026, blogs techniques, depots GitHub.

---

## 1. Tableau comparatif synthetique

| # | Outil | Positionnement | Modele | Cible | Differentiateur cle | Faiblesse principale |
|---|-------|----------------|--------|-------|---------------------|----------------------|
| 1 | **Detectify** | EASM + DAST crowdsource | SaaS - 90 a 302 EUR/mois et + | ETI / scale-ups produit | Crowdsource d'ethical hackers (payloads zero-day reels) | Volume d'actifs limite, peu de threat intel native, pas de scoring EPSS/KEV first-class |
| 2 | **MS Defender EASM** | Visibilite externe pilotee par Copilot | SaaS Azure - consumption-based | Grands comptes Azure | Copilot NLQ + integration Sentinel/Defender XDR | Lock-in Azure, peu utile sans le reste de la stack MS, fingerprinting moyen |
| 3 | **CyCognito** | Preemptive Exposure Management | SaaS enterprise | Grands comptes globaux | Decouverte "seedless" + 100k+ modules de test autonome | Faux positifs sur attribution algorithmique, support lent, pas aligne CTEM |
| 4 | **Cortex Xpanse** | Active ASM internet-scale | SaaS - ~95k USD/an pour 999 actifs | Grands comptes / Gov / Fortune 500 | Scan continu de l'IPv4 mondial + playbooks XSOAR | Prix prohibitif, complexite deploiement, workflow lourd |
| 5 | **Censys ASM** | Internet visibility (pas asset inventory) | SaaS enterprise | Grands comptes, telco, banque, gov | Carte Internet proprietaire 65535 ports + BGP + certificats | Cher, oriente decouverte plus que vulns applicatives |
| 6 | **Tenable ASM** | EASM dans exposure platform | SaaS - module Tenable One | ETI / grands comptes deja Tenable | 5+ milliards d'actifs indexes + Hexa AI + 200 metadata fields | Module annexe, pas une priorite produit, UX heritage |
| 7 | **Bishop Fox Cosmos** | Offensive ASM managed | Managed service haut de gamme | Fortune 1000 / regulated | Operateurs humains pentesteurs + Cosmos AI | Pas de self-service, prix premium, depend du staffing BF |
| 8 | **Mandiant ASM (Google)** | ASM + threat intel Mandiant | SaaS Google Cloud Security | Grands comptes / Gov | Threat intel Mandiant native + TTP-driven prioritization | Integre dans Google Security suite, parfois "second citoyen" |
| 9 | **OWASP Amass** | Mapping attack surface OSINT | Open source Apache 2.0 | Pentesters, red team, DIY | Communaute OWASP flagship + 150+ sources DNS/ASN | Pas de UI, pas de scoring, pas de monitoring continu |
| 10 | **ProjectDiscovery (Neo + Cloud)** | "Security at engineering speed" | OSS + SaaS Pro 1k actifs/mois | Bug bounty hunters, AppSec teams, DevSecOps | Nuclei community templates (12k+) + agentic pentesting | Couverture EASM "officielle" recente, dependance templates communaute |
| 11 | **Intrigue Core** | OSS attack surface discovery | Open source + offre entreprise | Red teams, chercheurs | Graphe d'attaque + API-first | Rewrite en cours, faible activite, peu de traction |

---

## 2. Fiches detaillees

### 2.1 Detectify

- **Tagline** : "Application security testing reimagined" - EASM + DAST nourris par une communaute d'ethical hackers.
- **Features cles** :
  - Surface Monitoring : decouverte continue domaines, sous-domaines, APIs, ressources cloud (AWS, Azure)
  - Application Scanning (DAST) : crawling + fuzzing + authentification multi-etat
  - Crowdsource : payloads reels soumis par 400+ hackers tries, integres aux scans en quelques heures
  - Detection de subdomain takeover, monitoring DNS, regles custom
  - Integrations Jira, Slack, Trello, Splunk
- **Modele economique** : Surface Monitoring ~302 EUR/mois pour 25 sous-domaines ; App Scanning 90 EUR/mois/domaine ; API Scanning 90 EUR/mois/API. Free trial 14 jours.
- **Cible** : ETI tech, scale-ups, equipes AppSec produit.
- **Differentiateur** : pipeline Crowdsource - les vulns trouvees par les chercheurs deviennent des tests automatises pour tous les clients (avantage zero-day verifiables).
- **Faiblesse** : pricing par sous-domaine penalise les gros parcs, pas de scoring EPSS/KEV first-class, threat intel inexistante, focus AppSec plus que ASM "entreprise".
- **Tech** : crawling avance, fuzzing, payload library propietaire, cloud-native (AWS), pas d'IA generative mise en avant.

### 2.2 Microsoft Defender EASM

- **Tagline** : "See your business the way an attacker can."
- **Features cles** :
  - Inventaire dynamique des assets internet-facing
  - Decouverte par graphe de relations (rachat de RiskIQ)
  - Detection de vulnerabilites/misconfigs sur frameworks, pages, composants
  - Identification du shadow IT et ressources non-managees
  - Multicloud (Azure, AWS, GCP)
  - **Copilot for Security** : requetes en langage naturel sur l'inventaire
- **Modele** : SaaS Azure, consumption-based (par asset/mois), bundle possible avec Defender XDR/Sentinel.
- **Cible** : grands comptes deja sur Azure / E5.
- **Differentiateur** : integration Copilot + Sentinel SIEM/XDR, base RiskIQ historique (graphe internet).
- **Faiblesse** : faux positifs frequents sur attribution, fingerprinting techno superficiel, peu d'orientation "vuln applicative", lock-in Azure.
- **Tech** : Azure, Copilot (GenAI), graphe RiskIQ, OWASP Top 10.

### 2.3 CyCognito

- **Tagline** : "Preemptive Exposure Management."
- **Features cles** :
  - **Seedless discovery** : pas besoin de fournir une liste d'actifs ; reconstruit l'arborescence corporate via OSINT
  - 100 000+ modules de test autonome (DAST, vuln scanning, brute force, config)
  - Inventaire d'actifs externes avec contexte business (subsidiaries, M&A, tiers)
  - Risk prioritization couplee exploit data + business impact
  - Workflow remediation owner-linked, validation autonome des fixes
  - 12+ integrations (ServiceNow, Splunk, Jira)
- **Modele** : SaaS enterprise, sans pricing public.
- **Cible** : Fortune 500 globales (Tesco, Colgate, Panasonic, Hitachi, Wipro, Deloitte).
- **Differentiateur** : decouverte d'actifs herites/M&A que les concurrents ratent + pentesting continu automatise.
- **Faiblesse** : "L'attribution algorithmique genere des faux positifs qui creent des conflits inter-equipes" (GigaOm 2026). Support lent. Pas aligne CTEM. Onboarding lourd.
- **Tech** : AI guided security tests, ML scoring, OSINT, bot networks de scan.

### 2.4 Palo Alto Cortex Xpanse

- **Tagline** : Active Attack Surface Management - decouvrir, apprendre, repondre.
- **Features cles** :
  - Scan continu de l'integralite de l'IPv4 (et services exposes)
  - ML supervise pour mapper l'attack surface et prioriser
  - Playbooks automatises (integration XSOAR)
  - Web ASM dedie aux applis web
  - Real-time alerting sur misconfigurations
- **Modele** : Subscription annuelle. Exemple public : 95 000 USD/an pour 999 actifs basic support. Tiering selon volume + features.
- **Cible** : Fortune 500, gov US, defense, telco.
- **Differentiateur** : echelle de scan "internet entier" + integration native dans la suite Cortex (XDR, XSOAR, XSIAM).
- **Faiblesse** : prix prohibitif pour ETI, deploiement complexe, valeur dependante de tout l'ecosysteme Cortex.
- **Tech** : ML supervise, internet-wide scanning, XSOAR, IPv4 mapping.

### 2.5 Censys ASM

- **Tagline** : "ASM Isn't Asset Inventory. It's Internet Visibility."
- **Features cles** :
  - Scan des 65 535 ports (incluant services non-standard, residentiels)
  - Up-to-the-hour visibility ("6x plus rapide que les ASM traditionnels")
  - Tracking certificats SSL/TLS (self-signed, certs reutilises)
  - Donnees historiques preservees, diff continu
  - Correlation ARC (rapid response advisories, threat intel)
  - Integrations SIEM / VM / ticketing
- **Modele** : SaaS enterprise, sans pricing public.
- **Cible** : SanDisk, Domino's, T-Mobile, Walmart, Bank of America, Bloomberg, AT&T, Raytheon, Merck.
- **Differentiateur** : carte Internet proprietaire (la plus complete avec Shodan), 1st-party scanning - voit ce que les autres ratent.
- **Faiblesse** : excellent en decouverte, faible en exploitation/scoring vuln applicatif, prix enterprise-only.
- **Tech** : Censys Internet Map, BGP, certificate transparency, scanners distribues.

### 2.6 Tenable ASM (Tenable One)

- **Tagline** : "Comprehensive visibility into internet-connected assets, services, applications" - integre a Tenable One exposure management.
- **Features cles** :
  - 5+ milliards d'assets internet-connected indexes
  - 200+ champs de metadata par actif
  - Monitoring continu + notifications de changement
  - Integration avec Nessus / Tenable VM / Tenable Cloud
  - Tagging, filtres, assignation
- **Modele** : module dans Tenable One, vendu en bundle.
- **Cible** : clients Tenable existants - banque, sante, industriel, ETI 1000+ employes.
- **Differentiateur** : continuum decouverte externe -> vuln management interne -> cloud (CNAPP). "Hexa AI" pour analyse.
- **Faiblesse** : module annexe (issu du rachat de Bit Discovery), UX/UI heritage, pas de focus webapp-first, threat intel basique.
- **Tech** : Hexa AI, scanners distribues, integration Nessus.

### 2.7 Bishop Fox Cosmos

- **Tagline** : "AI-Powered Application Penetration Testing - Scale Security Without Compromise."
- **Features cles** :
  - **Living asset inventory** : valide quotidiennement la reachability et le comportement protocolaire
  - Evidence-first scanning : screenshots, fingerprints, service metadata
  - Cloud-native, integration AWS/GCP/Azure/Cloudflare/Oracle API
  - Bi-directionnel Jira / ServiceNow
  - **Cosmos AI** (2026) : penetration testing augmente par IA
  - Modele opere - clients accedent via le portal BF
- **Modele** : Managed service haut de gamme (pas de self-service). Pricing sur devis, premium.
- **Cible** : Fortune 1000, regulated (banque, sante, gov).
- **Differentiateur** : operateurs humains pentesteurs valident chaque finding via Slack chiffre client + Customer Success Manager.
- **Faiblesse** : pas de produit en self-service, coute eleve, scalabilite dependante du staffing BF, pas adapte aux equipes qui veulent piloter.
- **Tech** : microservices stateless, Cosmos AI (annonce fev 2026), pipeline humain-machine.

### 2.8 Mandiant ASM (Google Cloud Security)

- **Tagline** : Visibilite continue de la surface d'attaque externe avec threat intel Mandiant.
- **Features cles** :
  - Decouverte / inventaire assets externes
  - Scanning continu misconfigurations & vulns
  - **Threat intel Mandiant** : TTPs reels, actors, campagnes
  - Monitoring changements en temps reel
  - Workflow remediation
  - Third-party risk assessment
- **Modele** : SaaS Google Cloud Security, vendu en bundle avec Chronicle / Security Command Center.
- **Cible** : grands comptes, gov, secteur regule.
- **Differentiateur** : threat intel Mandiant native (TTPs Mandiant + Frontline IR data) - prioritization basee sur ce que les attaquants utilisent reellement.
- **Faiblesse** : depuis l'acquisition Google, produit moins visible, integre dans une suite, perte d'attention vs Mandiant standalone.
- **Tech** : Mandiant Intel, Google Cloud, scanners distribues.

### 2.9 OWASP Amass

- **Tagline** : "In-depth attack surface mapping and asset discovery."
- **Features cles** :
  - Subdomain enumeration (passive + actif)
  - DNS reconnaissance
  - ASN mapping
  - 150+ sources OSINT
  - Network mapping graphe
  - Integration Maltego
  - CLI + API
- **Modele** : Apache 2.0, gratuit. 14.6k stars GitHub. Maintenance par Jeff Foley + communaute OWASP.
- **Cible** : pentesters, red team, bug bounty hunters, equipes securite DIY.
- **Differentiateur** : flagship OWASP, gratuit, modulaire, customisable. La reference open source.
- **Faiblesse** : CLI only, pas de UI, pas de scoring de vuln, pas de monitoring continu, pas de fingerprinting techno avance, pas d'integration entreprise.
- **Tech** : Go (99.6%), Docker, modulaire.

### 2.10 ProjectDiscovery (Nuclei, Subfinder, httpx + Cloud Platform / Neo)

- **Tagline** : "Security at Engineering Speed."
- **Features cles** :
  - **Nuclei** : moteur de templates YAML, 12 000+ templates communautaires
  - **Subfinder** : enumeration passive de sous-domaines (rapide, precis)
  - **httpx** : probing HTTP rapide
  - **Naabu, Katana, Chaos** : scan ports, crawling, dataset reconnaissance
  - **ProjectDiscovery Cloud Platform** : SaaS sur Nuclei, integration cloud (AWS/Azure/GCP), PDF reports, API
  - **Neo (2026)** : agents IA autonomes - AI Pentesting, PR Security Review, Threat Modeling, Vulnerability Remediation, Exposure Analysis
- **Modele** : OSS gratuit + SaaS freemium (free / team / enterprise). Pro tier ~1000 assets/mois.
- **Cible** : 100k+ professionnels - bug bounty hunters, AppSec teams, DevSecOps, MSSPs.
- **Differentiateur** : combo OSS le plus utilise au monde (Nuclei est devenu un standard de facto) + agents IA pour automatiser pentest/PR review.
- **Faiblesse** : couverture EASM "officielle" recente (cloud platform), depend de la qualite des templates communautaires, scoring/contextualisation business limite.
- **Tech** : Go, Anthropic Claude Agent SDK (Neo), YAML templates, AWS Marketplace.

### 2.11 Intrigue Core

- **Tagline** : "Discover Your Attack Surface."
- **Features cles** :
  - 150+ techniques de decouverte
  - Graphe d'attack surface
  - Machine files (automation)
  - API-first
  - CLI (core-cli)
- **Modele** : OSS + offre entreprise commerciale (Intrigue Corp, 2M USD leve).
- **Cible** : red teams, chercheurs, equipes securite avancees.
- **Differentiateur** : approche graphe + automation par "machine files".
- **Faiblesse** : rewrite en cours, traction faible, communaute reduite vs Amass/ProjectDiscovery, fork non maintenu depuis 2021 sur l'ancien repo.
- **Tech** : Ruby (historique), API REST, graphe.

---

## 3. Trous de marche identifies (= ou Pupelmet peut frapper)

Apres analyse croisee des 11 outils, voici les **lacunes communes** que personne ne couvre vraiment bien :

### 3.1 Web-first et fingerprinting techno applicatif profond
Les "grands" (Censys, Xpanse, Tenable) excellent en decouverte d'IP/ports mais font du fingerprinting web **superficiel**. Identifier qu'un site tourne sur Drupal 7.42 avec un plugin vulnerable specifique reste un trou. Detectify s'en rapproche cote DAST mais coute cher. **Pupelmet peut etre l'outil web-fingerprinting + CVE-mapping par defaut.**

### 3.2 Scoring EPSS + KEV first-class et explique
La plupart des outils enterprise font du "risk scoring" boite noire. Tres peu integrent **EPSS + CISA KEV explicites** comme criteres visibles avec leur weight. Purplemet l'a deja, c'est un atout - **a doubler : montrer "pourquoi cette CVE remonte en P1" avec evidence chain.**

### 3.3 Pricing transparent ETI
- Detectify : 302 EUR/25 subdomaines (vite cher)
- Xpanse : 95k USD/999 actifs (inaccessible)
- CyCognito / Censys / Mandiant : "contactez-nous"
- Bishop Fox : managed only

Aucun outil ASM n'offre un **pricing transparent et lineaire** sous 50k EUR/an pour 1000 actifs. Trou enorme pour ETI/scale-ups francaises et europeennes.

### 3.4 Detection des admin panels et "low-hanging fruits" exposes
Trouver un /admin, phpMyAdmin, Jenkins UI, Kibana sans auth, etc., est **rarement first-class** dans les outils ASM. Purplemet le fait deja, mais c'est sous-exploite chez les concurrents - a transformer en argument fort avec captures et POC.

### 3.5 Souverainete et conformite UE
Aucun acteur majeur europeen credible (Detectify est suedois mais raconte une histoire AppSec, pas souverainete). NIS2 / DORA / SecNumCloud creent une demande pour un **ASM UE-hebergé**, sans transfert vers US (Microsoft, Palo Alto, Google sont hors-jeu pour CAC40 prudent). **Pupelmet francais = arme commerciale.**

### 3.6 Veille passive sans scan agressif
Beaucoup de concurrents scannent agressivement (Xpanse, Censys), ce qui peut **alerter le SOC du client, declencher WAFs, voire enfreindre des regles legales** dans certains pays. Un mode 100% passif (CT logs, DNS, sources OSINT) avec scan actif opt-in et bornages legaux est un trou.

### 3.7 UX produit "PME-friendly" / time-to-value
Tous les enterprise (CyCognito, Xpanse, Censys, Tenable) ont un **onboarding lourd** (CyCognito : "initial onboarding can be time-intensive"). ProjectDiscovery est CLI. Detectify est plus simple mais limite. **Pupelmet peut viser "premier rapport en < 10 minutes apres saisie du domaine".**

### 3.8 Threat intel applicative live (pas juste CVE NVD)
Mandiant est seul a faire de la threat intel "vraie" (TTPs, campagnes), mais c'est cher et bundled. Les autres se contentent de NVD + EPSS + KEV. Personne ne fait **"cette stack expose-t-elle un actif exploite dans une campagne ransomware active de cette semaine ?"**. Couplage CVE -> campagne -> ransomware family = trou.

### 3.9 Agentic remediation guidance contextuel
Les concurrents donnent un score, un texte CVE generique, un lien NVD. **Personne ne genere une remediation contextuelle ("voici exactement la commande/PR pour patcher ce Drupal sur cette version")**. Avec Claude/LLM agentic, c'est faisable. ProjectDiscovery Neo s'y attaque cote pentest, mais pas remediation guidee multi-stack.

### 3.10 Monitoring continu avec "diff narratif" pour direction
Tous monitorent en continu, mais sortent des dashboards et tickets. **Aucun ne produit un "executive narrative weekly" du type : "cette semaine 3 actifs nouveaux, 1 CVE critique sur abc.com, baisse de risque de 8%, action requise."** Pour CISO ETI, c'est un gap concret.

### 3.11 Coverage des APIs et microservices modernes
Les outils ASM historiques (Tenable, Censys) sont nes a l'epoque des IIS/Apache. La vraie attack surface 2026 est **APIs, GraphQL, gRPC, supabase functions, edge functions, S3, blob, queues exposees**. Detectify a un module API mais limite. **Pupelmet peut etre API-aware natif.**

---

## 4. Tendances 2025-2026 - ce que tout le monde construit

### 4.1 Agentic AI dans le loop CTEM
Gartner predit que les **agents IA autonomes** vont prendre en charge le cycle "detect-investigate-remediate-verify" du CTEM d'ici 12-24 mois. ProjectDiscovery Neo, Bishop Fox Cosmos AI, Microsoft Copilot for Security, Tenable Hexa AI sont tous sur ce trajet. **Ce qui etait du SaaS classique en 2024 devient un "AI security operator" en 2026.**

### 4.2 Convergence ASM -> CTEM -> AEV
Gartner pousse trois acronymes qui convergent :
- **ASM** (decouverte)
- **CTEM** (Continuous Threat Exposure Management - prioritization continue)
- **AEV** (Adversarial Exposure Validation - simulation reelle d'attaque)

Tendance forte : **passer de "voici une liste de vulns" a "voici les chemins d'attaque exploitables aujourd'hui contre vous"**. Hadrian, Pentera, XM Cyber jouent deja a ce niveau.

### 4.3 Couverture du "shadow AI" et MCP servers
Nouvelle attack surface : **agents IA, prompts caches, MCP servers, modeles deployes en cloud, no-code/vibe coding** generent des exposures non gerees. Aucun outil ne les couvre encore mais c'est annonce par Gartner comme priorite 2026-2027.

### 4.4 Regulation comme driver d'achat
NIS2, DORA, PCI DSS 4.0.1 obligent au monitoring continu. **L'ASM devient un must-have legal**, pas juste un nice-to-have. Argument de vente clair pour Pupelmet sur le marche EU.

### 4.5 Prioritization basee exploit reel (EPSS + KEV + threat intel)
Standard de fait emergeant : pas que CVSS, mais EPSS + KEV + threat intel campagne. Purplemet est deja la-dessus - bonne base.

### 4.6 Plateformes unifiees vs pure players
**Tendance fusion** : Tenable (VM+ASM+CNAPP), Microsoft (Defender suite), Palo Alto (Cortex), Google (Mandiant+SCC). Les pure players (Detectify, CyCognito, Censys) se font absorber ou se specialisent.
**Implication Pupelmet** : pour rester pure player, il faut **etre le meilleur sur un segment etroit** (ex: web app discovery + CVE mapping ETI EU) ou viser l'integration native dans les SIEM EU (Tehtris, Sekoia).

### 4.7 Open source en pression haute sur le bas du marche
ProjectDiscovery (Nuclei) + Amass + OSS commoditisent la **decouverte de base**. Les editeurs payants doivent justifier leur prix par : threat intel, contextualisation business, remediation, MSP workflow, conformite. **Pupelmet doit etre clair sur "qu'apporte-t-on que Nuclei + Amass + script Python ne donne pas ?"**

### 4.8 Modele MSSP / channel
Plusieurs concurrents (CyCognito, Bishop Fox, Cortex) misent sur les MSSP comme canal. **Marche ETI francais : passer par les Almond, Advens, Sopra Steria, Wavestone est un canal sous-exploite par les editeurs etrangers.**

### 4.9 Integration native dans le workflow dev
Detectify, ProjectDiscovery, Bishop Fox font tous des integrations Jira/ServiceNow/Slack. Tendance : **shift-left avec PR scanning + IaC + DAST en CI**. Tres peu d'ASM s'integrent reellement dans la chaine CI/CD developpeur.

### 4.10 Threat intel "live" et campagnes ransomware
Mandiant est leader. ProjectDiscovery integre l'actu CVE en quasi-temps reel via templates Nuclei. **Tendance : passer du CVE statique au "vulnerability + campaign + actor + ransomware family" en un seul lien.**

---

## 5. Synthese pour Pupelmet - axes d'attaque recommandes

1. **Verticale "Web ASM pour ETI EU"** : transparent pricing, hebergement souverain, conformite NIS2/DORA native.
2. **Fingerprinting techno + CVE/EPSS/KEV explique** : pas une boite noire, evidence chain visible.
3. **Time-to-value < 10 min** : faire ce que CyCognito et Xpanse n'arrivent pas a faire - un onboarding instant.
4. **Agentic remediation guidance** : LLM contextuel ("voici la PR pour patcher").
5. **Detection admin panels / shadow apps / API exposees** : double down sur les "low-hanging fruits" que personne ne montre bien.
6. **Veille passive opt-actif** : conformite RGPD/legal sur la collecte.
7. **Channel MSSP francais** : Advens, Almond, Sopra, Wavestone, Sekoia comme canal.
8. **Narratif executif hebdomadaire** : sortie "CISO ready" pas que dashboard.
9. **API-first ASM** : couvrir Supabase, Vercel, Cloudflare Workers, gRPC, GraphQL natifs.
10. **Integration SIEM EU** (Sekoia, Tehtris) + workflow Jira/ServiceNow standard.

---

## Sources principales

- Detectify.com, blog.detectify.com, G2 Detectify Reviews 2026
- Microsoft Defender EASM product page (microsoft.com/security)
- CyCognito.com, GigaOm Radar ASM 2026, G2 CyCognito Reviews 2026, IONIX comparatif 2026
- Palo Alto Cortex Xpanse (paloaltonetworks.com), PeerSpot pricing 2026
- Censys.com/product/attack-surface-management
- Tenable.com/products/tenable-asm, Tenable One pricing
- Bishop Fox Cosmos (bishopfox.com/services/cosmos), AWS Marketplace, Dark Reading 2026
- Cloud.google.com/security/products/attack-surface-management (Mandiant)
- GitHub owasp-amass/amass (14.6k stars, Apache 2.0)
- ProjectDiscovery.io blog "Announcing PDCP", Nuclei community templates
- Intrigue Core (core.intrigue.io, github.com/intrigueio)
- Gartner 2026 Market Guide for Adversarial Exposure Validation
- Gartner Top Cybersecurity Trends 2026 (newsroom feb 2026)
- The Hacker News "CTEM Divide" feb 2026
- Vectra "CTEM explained: Gartner's 5 stages and 2026 prediction"
- Hadrian.io "What the 2026 Gartner Market Guide for AEV means"

---

*Document genere le 2026-05-18 pour le projet Pupelmet. Rapport dense, sans blabla marketing, focalise sur les decisions produit a prendre.*
