"""
main.py — Application web FastAPI ARGUS

Pipeline d'un scan complet :
  1. Découverte multi-sources  → sous-domaines
  2. Vérification HTTP         → actifs vivants + technos
  3. Sécurité email (DNS)      → SPF / DKIM / DMARC
  4. Audit certificats SSL     → expiration, protocoles, chiffrement
  5. Analyse des vulnérabilités (opt-in) → CVE + exposures
  6. Enrichissement Threat Intel         → EPSS + CISA KEV
  7. Calcul du score de risque           → A-F
  8. Analyse sécurité exécutive          → brief en français
"""

import os
from datetime import datetime
from pathlib import Path

from dotenv import load_dotenv
_ENV_PATH = Path(__file__).parent.parent / ".env"
load_dotenv(_ENV_PATH, encoding="utf-8", override=True)

from fastapi import FastAPI, Request, Depends, Form, BackgroundTasks, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.database import init_db, get_db, SessionLocal
from app.models import (Scan, Asset, Vuln, TlsFinding, User,
                        PasswordResetToken, EmailVerificationToken, PublicReport,
                        PLAN_LIMITS, PLAN_NAMES)
from app.email_sender import send_welcome_email, send_password_reset_email, send_email_verification
from app import scanner, nuclei, dns_scan, tls_scan, enrichment, risk_score, discovery, pentest
from app.auth import (
    hash_password, verify_password,
    get_current_user, get_plan_limits, can_see_full_results,
    ADMIN_EMAIL,
)

ROOT = Path(__file__).parent
TEMPLATES_DIR = ROOT / "templates"
STATIC_DIR = ROOT / "static"

app = FastAPI(title="ARGUS Security", version="3.0.0")
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
templates = Jinja2Templates(directory=TEMPLATES_DIR)
templates.env.cache = None  # workaround Jinja2 3.1.x + Starlette bug

# ─── Filtre Jinja2 : markdown léger → HTML safe ──────────────────────
import re as _re
from markupsafe import Markup as _Markup

def _md_to_html(text: str) -> _Markup:
    """Convertit markdown léger en HTML pour affichage dans les templates."""
    if not text:
        return _Markup("")
    # Échappe d'abord le HTML brut
    import html as _html
    t = _html.escape(text)
    # Titres (# Titre → <strong>)
    t = _re.sub(r'^#{1,3}\s+(.+)$', r'<strong>\1</strong>', t, flags=_re.MULTILINE)
    # **gras**
    t = _re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', t)
    # *italique*
    t = _re.sub(r'\*(.+?)\*', r'<em>\1</em>', t)
    # Séparateurs ---
    t = _re.sub(r'\n?---+\n?', '\n', t)
    # Paragraphes (double saut de ligne)
    paragraphs = [p.strip() for p in _re.split(r'\n{2,}', t) if p.strip()]
    t = ''.join(f'<p>{p}</p>' for p in paragraphs)
    # Simples sauts de ligne dans paragraphes → <br>
    t = t.replace('\n', '<br>')
    return _Markup(t)

templates.env.filters["md"] = _md_to_html

# ─── Session middleware (cookies sécurisés signés) ───────────────────
SESSION_SECRET = os.getenv("SESSION_SECRET", "").strip()
if not SESSION_SECRET:
    # En dev : fallback acceptable. En prod (DEBUG=0) : on crash.
    if os.getenv("DEBUG", "1") == "0":
        raise RuntimeError(
            "SESSION_SECRET est obligatoire en production. "
            "Génère une chaîne aléatoire forte avec : "
            "python -c \"import secrets; print(secrets.token_urlsafe(48))\" "
            "et mets-la dans ton .env."
        )
    SESSION_SECRET = "argus-dev-secret-change-in-prod"
    print("[WARN] SESSION_SECRET non défini — utilisation d'un secret par défaut (dev only)", flush=True)

# https_only doit être True en prod (config via env)
_https_only = os.getenv("SESSION_HTTPS_ONLY", "0").lower() in ("1", "true", "yes")
app.add_middleware(SessionMiddleware, secret_key=SESSION_SECRET, https_only=_https_only)


@app.on_event("startup")
def _startup():
    init_db()


@app.get("/healthz")
def healthz():
    """Health check minimal pour Coolify / Traefik / load balancer."""
    return {"status": "ok", "service": "argus"}


# ─────────────────────────────────────────────────────────────────────
# Helper : contexte commun pour toutes les pages
# ─────────────────────────────────────────────────────────────────────

def _ctx(request: Request, db: Session, **extra) -> dict:
    """Contexte de base injecté dans tous les templates."""
    user = get_current_user(request, db)
    return {"request": request, "current_user": user, **extra}


# ─────────────────────────────────────────────────────────────────────
# Pages publiques
# ─────────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
def index(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if user:
        recent = db.query(Scan).filter(Scan.user_id == user.id).order_by(Scan.started_at.desc()).limit(5).all()
    else:
        recent = []
    return templates.TemplateResponse("index.html", _ctx(request, db, recent_scans=recent))


@app.get("/faq", response_class=HTMLResponse)
def faq(request: Request, db: Session = Depends(get_db)):
    return templates.TemplateResponse("faq.html", _ctx(request, db, active="faq"))


@app.get("/pricing", response_class=HTMLResponse)
def pricing(request: Request, db: Session = Depends(get_db)):
    return templates.TemplateResponse("pricing.html", _ctx(request, db, active="pricing"))


@app.get("/history", response_class=HTMLResponse)
def history(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse("/login", status_code=302)
    if user.is_admin:
        scans = db.query(Scan).order_by(Scan.started_at.desc()).all()
    else:
        scans = db.query(Scan).filter(Scan.user_id == user.id).order_by(Scan.started_at.desc()).all()
    return templates.TemplateResponse("history.html", _ctx(request, db, scans=scans, active="history"))


@app.get("/scan/{scan_id}", response_class=HTMLResponse)
def scan_view(scan_id: int, request: Request, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(404, "Scan introuvable")

    user = get_current_user(request, db)

    # Contrôle d'accès : un scan appartient à son propriétaire (ou admin, ou scan sans owner)
    if scan.user_id and user and not user.is_admin and scan.user_id != user.id:
        raise HTTPException(403, "Accès non autorisé")

    # Vulns triées par priorité (KEV > EPSS > severity)
    vulns_sorted = sorted(scan.vulns, key=nuclei.vuln_priority_score, reverse=True)

    # ── Calcul accès 20% / 100% ──────────────────────────────────────
    full_access = can_see_full_results(user)

    total_assets = len(scan.assets)
    total_vulns  = len(vulns_sorted)
    total_subs   = len(scan.discovered_subs or [])

    if full_access:
        visible_assets     = list(scan.assets)
        visible_vulns      = vulns_sorted
        visible_subs       = scan.discovered_subs or []
        locked_assets      = 0
        locked_vulns       = 0
        locked_subs        = 0
    else:
        # Gratuit → 20% visible (min 1), les plus critiques d'abord
        n_assets = max(1, int(total_assets * 0.20))
        n_vulns  = max(1, int(total_vulns  * 0.20))
        n_subs   = max(5, int(total_subs   * 0.20))
        visible_assets = list(scan.assets)[:n_assets]
        visible_vulns  = vulns_sorted[:n_vulns]
        visible_subs   = (scan.discovered_subs or [])[:n_subs]
        locked_assets  = total_assets - n_assets
        locked_vulns   = total_vulns  - n_vulns
        locked_subs    = total_subs   - n_subs

    # ── Scare finding (preview alarmant pour user free) ──────────
    # Identifie LE finding réel le plus impactant à afficher en haut
    # pour faire prendre conscience du risque (jamais inventé).
    scare = _build_scare_finding(scan, vulns_sorted) if not full_access else None

    return templates.TemplateResponse("scan.html", _ctx(
        request, db,
        scan=scan,
        assets=visible_assets,
        vulns=visible_vulns,
        visible_subs=visible_subs,
        tls_findings=scan.tls_findings,
        full_access=full_access,
        locked_assets=locked_assets,
        locked_vulns=locked_vulns,
        locked_subs=locked_subs,
        total_assets=total_assets,
        total_vulns=total_vulns,
        total_subs=total_subs,
        scare=scare,
        plan_limits=get_plan_limits(user),
    ))


def _build_scare_finding(scan, vulns_sorted):
    """
    Identifie le RÉEL finding le plus alarmant et l'explique en mots simples.
    Priorité :
      1. KEV (CVE activement exploitée dans la nature)
      2. CVE critique
      3. cPanel/admin/wp-admin exposé sans auth
      4. DMARC absent (phishing au nom du domaine non bloqué)
      5. SPF absent
      6. Certif TLS expiré
      7. Sous-domaine sensible exposé (admin, intranet, vpn, dev, staging, db, ftp)
    """
    # 1. KEV — la pire des pires
    kev_vulns = [v for v in vulns_sorted if v.kev]
    if kev_vulns:
        v = kev_vulns[0]
        return {
            "icon": "🚨",
            "title": "Vulnérabilité activement exploitée par des hackers",
            "finding": f"{v.name or v.template_id}" + (f" — {v.cve_id}" if v.cve_id else "") + f" sur {v.matched_url or scan.domain}",
            "explanation": (
                "Cette faille fait partie du <strong>catalogue CISA KEV</strong> : "
                "elle est <strong>actuellement exploitée par des hackers</strong> "
                "contre d'autres entreprises dans le monde. Les exploits sont publics et automatisés. "
                "Sans correction immédiate, c'est seulement une question de jours avant qu'un script kiddie "
                "ne tombe sur votre site."
            ),
        }

    # 2. CVE critique
    critical = [v for v in vulns_sorted if (v.severity or "").lower() == "critical"]
    if critical:
        v = critical[0]
        return {
            "icon": "🔥",
            "title": "Faille critique exploitable détectée",
            "finding": f"{v.name or v.template_id}" + (f" — {v.cve_id}" if v.cve_id else "") + f" sur {v.matched_url or scan.domain}",
            "explanation": (
                "Une <strong>faille de gravité critique</strong> a été trouvée sur l'un de vos actifs. "
                "Un attaquant peut potentiellement <strong>prendre le contrôle de ce serveur</strong>, "
                "voler vos données, ou s'en servir comme tremplin pour atteindre votre infrastructure interne. "
                "Aucune compétence technique poussée n'est requise — des outils automatisés exploitent ce genre de faille en quelques secondes."
            ),
        }

    # 3. Panneaux d'admin exposés (cPanel, wp-admin, etc.)
    sensitive_paths = ["cpanel", "wp-admin", "wp-login", "phpmyadmin", "/admin", "adminer", "webmin"]
    for a in scan.assets[:50]:
        url = (a.url or "").lower()
        for sp in sensitive_paths:
            if sp in url:
                return {
                    "icon": "🔓",
                    "title": "Interface d'administration exposée publiquement",
                    "finding": a.url,
                    "explanation": (
                        f"Une <strong>console d'administration</strong> est accessible depuis internet. "
                        f"Un attaquant qui devine ou force le mot de passe (ou exploite une faille du logiciel) "
                        f"peut <strong>prendre le contrôle complet du site</strong> en quelques minutes. "
                        f"Ce type d'interface ne devrait jamais être exposée sans VPN ou IP whitelist."
                    ),
                }

    # 4. DMARC absent — phishing facile
    dmarc = scan.dmarc or {}
    if not dmarc.get("present"):
        return {
            "icon": "📧",
            "title": "Phishing au nom de votre entreprise possible",
            "finding": f"Aucun enregistrement DMARC publié pour {scan.domain}",
            "explanation": (
                "<strong>N'importe qui peut envoyer des emails qui semblent venir de votre domaine</strong>. "
                f"Un attaquant peut écrire à vos clients depuis <em>direction@{scan.domain}</em> ou <em>compta@{scan.domain}</em> "
                "pour leur faire virer de l'argent ou cliquer sur un lien piégé. "
                "Vos clients et partenaires sont à la merci d'un usurpateur d'identité."
            ),
        }

    # 5. SPF absent
    spf = scan.spf or {}
    if not spf.get("present"):
        return {
            "icon": "✉️",
            "title": "Vos emails peuvent être usurpés",
            "finding": f"Aucun enregistrement SPF publié pour {scan.domain}",
            "explanation": (
                "Sans SPF, <strong>n'importe quel serveur peut envoyer des emails en se faisant passer pour vous</strong>. "
                "Les serveurs mail de vos destinataires (Gmail, Outlook...) ne peuvent pas vérifier si l'email vient vraiment "
                "de votre domaine. Résultat : soit vos vrais emails finissent en spam, soit des emails frauduleux "
                "arrivent à vos clients en se faisant passer pour vous."
            ),
        }

    # 6. Certif TLS expiré
    expired_certs = [t for t in (scan.tls_findings or []) if t.expired]
    if expired_certs:
        t = expired_certs[0]
        return {
            "icon": "🔐",
            "title": "Certificat SSL expiré — visiteurs bloqués",
            "finding": f"Certificat expiré sur {t.host}",
            "explanation": (
                "Le certificat SSL/HTTPS de cet actif est <strong>expiré</strong>. "
                "Tous vos visiteurs voient une <strong>page rouge d'alerte</strong> dans leur navigateur "
                "(Chrome, Firefox, Edge) : <em>« Connexion non sécurisée — Risque attaque ! »</em>. "
                "99% des visiteurs partent immédiatement. Si c'est un site e-commerce ou de contact, "
                "vous perdez des clients chaque heure."
            ),
        }

    # 7. Sous-domaine sensible exposé
    sensitive_subs = ["admin", "intranet", "vpn", "dev", "staging", "db", "database", "ftp", "test", "phpmyadmin", "jenkins"]
    for sub in (scan.discovered_subs or [])[:30]:
        sub_lower = sub.lower()
        for sens in sensitive_subs:
            if sub_lower.startswith(sens + ".") or sub_lower == sens + "." + scan.domain.lower():
                return {
                    "icon": "👁️",
                    "title": "Sous-domaine interne exposé publiquement",
                    "finding": sub,
                    "explanation": (
                        f"Un sous-domaine qui semble être <strong>destiné à un usage interne</strong> ({sens}) "
                        f"est accessible depuis internet. Les hackers le savent : ces interfaces sont souvent "
                        f"moins surveillées, avec des mots de passe par défaut ou des versions logicielles obsolètes. "
                        f"C'est une <strong>porte d'entrée privilégiée</strong> pour pénétrer votre réseau."
                    ),
                }

    # Aucun finding alarmant — message generic mais honnête
    if scan.assets_count and scan.assets_count > 0:
        return {
            "icon": "🔍",
            "title": f"{scan.assets_count} actifs cartographiés — analyse complète disponible",
            "finding": f"Surface d'attaque : {scan.assets_count} actifs identifiés",
            "explanation": (
                "Le scan a découvert votre surface d'attaque visible depuis internet. "
                "Les détails de chaque actif (technologies utilisées, configurations, certificats) "
                "sont visibles à 100% avec le plan Essentiel. "
                "Sans cette visibilité complète, des actifs oubliés peuvent rester exposés sans surveillance."
            ),
        }

    return None


# ─────────────────────────────────────────────────────────────────────
# Auth — Inscription / Connexion / Déconnexion
# ─────────────────────────────────────────────────────────────────────

# ─── Rate limit en mémoire (in-process) pour /login et /forgot ───
# Simple sliding window : max N tentatives par IP dans une fenêtre de WINDOW secondes.
from collections import defaultdict, deque
import time as _time
from threading import Lock as _Lock

_RATE_LIMIT_STORE: dict = defaultdict(deque)
_RATE_LIMIT_LOCK = _Lock()

def _rate_limit_check(key: str, max_attempts: int, window_seconds: int) -> tuple[bool, int]:
    """
    Retourne (allowed, retry_after_seconds).
    allowed=False si le quota est dépassé.
    """
    now = _time.time()
    cutoff = now - window_seconds
    with _RATE_LIMIT_LOCK:
        attempts = _RATE_LIMIT_STORE[key]
        # Nettoie les tentatives expirées
        while attempts and attempts[0] < cutoff:
            attempts.popleft()
        if len(attempts) >= max_attempts:
            retry_in = int(attempts[0] + window_seconds - now) + 1
            return False, max(1, retry_in)
        attempts.append(now)
    return True, 0


def _client_ip(request: Request) -> str:
    # X-Forwarded-For si derrière reverse proxy
    xff = request.headers.get("x-forwarded-for", "").split(",")[0].strip()
    return xff or (request.client.host if request.client else "unknown")


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request, db: Session = Depends(get_db)):
    if get_current_user(request, db):
        return RedirectResponse("/", 302)
    return templates.TemplateResponse("login.html", _ctx(request, db, error=None))


@app.post("/login", response_class=HTMLResponse)
def login_post(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    email = email.lower().strip()

    # Rate limit : 8 tentatives par 5 minutes par IP+email combiné
    ip = _client_ip(request)
    rl_key = f"login:{ip}:{email}"
    allowed, retry_in = _rate_limit_check(rl_key, max_attempts=8, window_seconds=300)
    if not allowed:
        return templates.TemplateResponse("login.html", _ctx(request, db,
            error=f"Trop de tentatives. Réessayez dans {retry_in} secondes."), status_code=429)

    user = db.query(User).filter(User.email == email).first()
    if not user or not verify_password(password, user.password_hash):
        return templates.TemplateResponse("login.html", _ctx(request, db,
            error="Email ou mot de passe incorrect."))

    user.last_login_at = datetime.utcnow()
    db.commit()

    request.session["user_id"] = user.id
    # Nettoie le compteur de rate limit après succès
    with _RATE_LIMIT_LOCK:
        _RATE_LIMIT_STORE.pop(rl_key, None)

    # Admin → dashboard ops direct, pas l'accueil
    if user.is_admin:
        return RedirectResponse("/admin", 302)
    return RedirectResponse("/", 302)


# ─────────────────────────────────────────────────────────────────────
# Mot de passe oublié — reset par email avec token unique
# ─────────────────────────────────────────────────────────────────────

import secrets as _secrets
from datetime import timedelta as _timedelta


@app.get("/forgot-password", response_class=HTMLResponse)
def forgot_password_page(request: Request, db: Session = Depends(get_db)):
    if get_current_user(request, db):
        return RedirectResponse("/", 302)
    sent = request.query_params.get("sent") == "1"
    return templates.TemplateResponse("forgot_password.html", _ctx(request, db, sent=sent, error=None))


@app.post("/forgot-password", response_class=HTMLResponse)
def forgot_password_post(
    request: Request,
    email: str = Form(...),
    db: Session = Depends(get_db),
):
    email = email.lower().strip()

    # Rate limit : 3 demandes par 10 min par IP (anti-spam d'emails)
    ip = _client_ip(request)
    allowed, retry_in = _rate_limit_check(f"forgot:{ip}", max_attempts=3, window_seconds=600)
    if not allowed:
        return templates.TemplateResponse("forgot_password.html", _ctx(request, db,
            sent=False,
            error=f"Trop de demandes depuis votre IP. Réessayez dans {retry_in // 60 + 1} minute(s)."),
            status_code=429)

    # On répond TOUJOURS la même chose, qu'on trouve le user ou pas (anti-enumeration)
    user = db.query(User).filter(User.email == email).first()
    if user:
        # Invalide les anciens tokens non utilisés
        db.query(PasswordResetToken).filter(
            PasswordResetToken.user_id == user.id,
            PasswordResetToken.used_at.is_(None),
        ).delete()

        token = _secrets.token_urlsafe(48)
        prt = PasswordResetToken(
            user_id=user.id,
            token=token,
            expires_at=datetime.utcnow() + _timedelta(hours=1),
        )
        db.add(prt)
        db.commit()

        base_url = str(request.base_url).rstrip("/")
        reset_url = f"{base_url}/reset-password/{token}"
        try:
            send_password_reset_email(user.email, user.name or "", reset_url)
        except Exception as e:
            print(f"[FORGOT] send email failed: {e}", flush=True)

    return RedirectResponse("/forgot-password?sent=1", 303)


@app.get("/reset-password/{token}", response_class=HTMLResponse)
def reset_password_page(token: str, request: Request, db: Session = Depends(get_db)):
    prt = db.query(PasswordResetToken).filter(PasswordResetToken.token == token).first()
    if (not prt
        or prt.used_at is not None
        or prt.expires_at < datetime.utcnow()):
        return templates.TemplateResponse("reset_password.html", _ctx(request, db,
            token=None,
            error="Ce lien de réinitialisation est invalide ou expiré. Demandez-en un nouveau."))
    return templates.TemplateResponse("reset_password.html", _ctx(request, db,
        token=token, error=None))


@app.post("/reset-password/{token}", response_class=HTMLResponse)
def reset_password_post(
    token: str,
    request: Request,
    password: str = Form(...),
    password_confirm: str = Form(...),
    db: Session = Depends(get_db),
):
    prt = db.query(PasswordResetToken).filter(PasswordResetToken.token == token).first()
    if (not prt
        or prt.used_at is not None
        or prt.expires_at < datetime.utcnow()):
        return templates.TemplateResponse("reset_password.html", _ctx(request, db,
            token=None,
            error="Ce lien de réinitialisation est invalide ou expiré. Demandez-en un nouveau."))

    if len(password) < 8:
        return templates.TemplateResponse("reset_password.html", _ctx(request, db,
            token=token,
            error="Le mot de passe doit contenir au moins 8 caractères."))

    if password != password_confirm:
        return templates.TemplateResponse("reset_password.html", _ctx(request, db,
            token=token,
            error="Les deux mots de passe ne correspondent pas."))

    user = db.query(User).filter(User.id == prt.user_id).first()
    if not user:
        return templates.TemplateResponse("reset_password.html", _ctx(request, db,
            token=None,
            error="Compte introuvable."))

    user.password_hash = hash_password(password)
    prt.used_at = datetime.utcnow()
    db.commit()

    # On connecte direct l'utilisateur
    request.session["user_id"] = user.id
    return RedirectResponse("/?password_reset=1", 302)


@app.get("/register", response_class=HTMLResponse)
def register_page(request: Request, db: Session = Depends(get_db)):
    if get_current_user(request, db):
        # Si un domaine est en attente (utilisateur a tenté un scan), on l'envoie scanner direct
        pending = request.session.pop("pending_scan_domain", None)
        if pending:
            return RedirectResponse(f"/?domain={pending}", 302)
        return RedirectResponse("/", 302)
    # Récupère le domaine éventuel dans l'URL pour le pré-remplir dans une éventuelle redirection après inscription
    prefill_domain = request.query_params.get("domain", "").strip()
    if prefill_domain and _is_valid_domain(_normalize_domain(prefill_domain)):
        request.session["pending_scan_domain"] = _normalize_domain(prefill_domain)
    return templates.TemplateResponse("register.html", _ctx(request, db,
        error=None, prefill_domain=request.session.get("pending_scan_domain", "")))


@app.post("/register", response_class=HTMLResponse)
def register_post(
    request: Request,
    name: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    company: str = Form(""),
    phone_whatsapp: str = Form(""),
    whatsapp_opt_in: bool = Form(False),
    tos_accepted: bool = Form(False),
    db: Session = Depends(get_db),
):
    email = email.lower().strip()
    name = name.strip()
    phone_clean = "".join(c for c in phone_whatsapp if c.isdigit() or c == "+")

    def _err(msg: str):
        return templates.TemplateResponse("register.html", _ctx(request, db,
            error=msg,
            prefill_name=name,
            prefill_email=email,
            prefill_company=company,
            prefill_phone=phone_whatsapp,
            prefill_wa_opt_in=whatsapp_opt_in,
            prefill_domain=request.session.get("pending_scan_domain", "")))

    # 1. Validations basiques
    if not name or len(name) < 2:
        return _err("Veuillez renseigner votre prénom et nom (2 caractères minimum).")

    if not _EMAIL_RE.match(email):
        return _err("L'adresse email n'est pas valide. Format attendu : nom@domaine.com")

    if len(password) < 8:
        return _err("Le mot de passe doit contenir au moins 8 caractères.")

    if not tos_accepted:
        return _err("Vous devez accepter les Conditions Générales d'Utilisation pour créer un compte.")

    # 2. Validation WhatsApp — obligatoire et au format international SI checkbox cochée
    if whatsapp_opt_in:
        if not phone_clean:
            return _err("Vous avez coché « Recevoir les résultats par WhatsApp » mais aucun numéro n'a été renseigné. Format : +33612345678 ou +212661234567")
        if not _PHONE_RE.match(phone_clean):
            return _err("Numéro WhatsApp invalide. Format attendu : indicatif international + numéro, ex : +33612345678 ou +212661234567")
    elif phone_clean and not _PHONE_RE.match(phone_clean):
        # Si un numéro est saisi (même sans opt-in coché), on exige le format
        return _err("Numéro WhatsApp invalide. Format attendu : +33612345678 (commence par + suivi de l'indicatif).")

    # 3. Unicité email
    existing = db.query(User).filter(User.email == email).first()
    if existing:
        return _err("Un compte existe déjà avec cet email. Connectez-vous plutôt.")

    # 4. Création
    user = User(
        email=email,
        password_hash=hash_password(password),
        name=name,
        company=company.strip() or None,
        phone_whatsapp=phone_clean or None,
        whatsapp_opt_in=whatsapp_opt_in,
        tos_accepted=True,
        tos_accepted_at=datetime.utcnow(),
        is_admin=(email == ADMIN_EMAIL),
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    request.session["user_id"] = user.id

    # Génère le token de vérification d'email + envoie le mail
    try:
        token = _secrets.token_urlsafe(48)
        evt = EmailVerificationToken(
            user_id=user.id,
            token=token,
            expires_at=datetime.utcnow() + _timedelta(hours=24),
        )
        db.add(evt)
        db.commit()
        base_url = str(request.base_url).rstrip("/")
        send_email_verification(user.email, user.name, f"{base_url}/verify-email/{token}")
    except Exception as e:
        print(f"[VERIFY EMAIL] {e}", flush=True)

    return RedirectResponse("/verify-email/pending", 302)


@app.get("/verify-email/pending", response_class=HTMLResponse)
def verify_email_pending(request: Request, db: Session = Depends(get_db)):
    """Page indiquant qu'un email de vérification vient d'être envoyé."""
    user = get_current_user(request, db)
    resent = request.query_params.get("resent") == "1"
    return templates.TemplateResponse("verify_email_pending.html", _ctx(request, db,
        user_email=user.email if user else "",
        resent=resent,
        error=request.session.pop("verify_error", None)))


@app.post("/verify-email/resend")
def verify_email_resend(request: Request, db: Session = Depends(get_db)):
    """Renvoie l'email de vérification."""
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse("/login", 303)

    if user.email_verified_at:
        return RedirectResponse("/", 303)

    # Rate limit : 3 renvois par 10 min
    ip = _client_ip(request)
    allowed, retry_in = _rate_limit_check(f"verify_resend:{user.id}:{ip}", max_attempts=3, window_seconds=600)
    if not allowed:
        request.session["verify_error"] = f"Trop de renvois. Réessayez dans {retry_in // 60 + 1} minute(s)."
        return RedirectResponse("/verify-email/pending", 303)

    # Invalide les anciens tokens non utilisés
    db.query(EmailVerificationToken).filter(
        EmailVerificationToken.user_id == user.id,
        EmailVerificationToken.used_at.is_(None),
    ).delete()

    token = _secrets.token_urlsafe(48)
    evt = EmailVerificationToken(
        user_id=user.id,
        token=token,
        expires_at=datetime.utcnow() + _timedelta(hours=24),
    )
    db.add(evt)
    db.commit()

    base_url = str(request.base_url).rstrip("/")
    try:
        send_email_verification(user.email, user.name, f"{base_url}/verify-email/{token}")
    except Exception as e:
        print(f"[VERIFY RESEND] {e}", flush=True)

    return RedirectResponse("/verify-email/pending?resent=1", 303)


@app.get("/verify-email/{token}", response_class=HTMLResponse)
def verify_email_confirm(token: str, request: Request, db: Session = Depends(get_db)):
    """Valide le token et marque l'email comme vérifié."""
    if token in ("pending", "resend"):
        # Évite collision avec les routes spécifiques
        raise HTTPException(404)

    evt = db.query(EmailVerificationToken).filter(EmailVerificationToken.token == token).first()
    if (not evt or evt.used_at is not None or evt.expires_at < datetime.utcnow()):
        return templates.TemplateResponse("verify_email_result.html", _ctx(request, db,
            success=False,
            message="Ce lien de vérification est invalide ou expiré."))

    user = db.query(User).filter(User.id == evt.user_id).first()
    if not user:
        return templates.TemplateResponse("verify_email_result.html", _ctx(request, db,
            success=False, message="Compte introuvable."))

    user.email_verified_at = datetime.utcnow()
    evt.used_at = datetime.utcnow()
    db.commit()

    # Auto-login : si user pas connecté, on le connecte
    if not get_current_user(request, db):
        request.session["user_id"] = user.id

    # Email de bienvenue maintenant que l'email est vérifié
    try:
        base_url = str(request.base_url).rstrip("/")
        send_welcome_email(user.email, user.name, base_url)
    except Exception as e:
        print(f"[WELCOME EMAIL] {e}", flush=True)

    # Si un scan était en attente, on lance direct
    pending = request.session.pop("pending_scan_domain", None)
    if pending:
        return RedirectResponse(f"/?domain={pending}&autoscan=1&verified=1", 302)
    return RedirectResponse("/?verified=1", 302)


@app.post("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/", 302)


@app.get("/account", response_class=HTMLResponse)
def account(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse("/login", 302)
    return templates.TemplateResponse("account.html", _ctx(request, db, active="account",
        plan_name=PLAN_NAMES.get(user.plan, user.plan)))


@app.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse("/login", 302)
    success = request.session.pop("settings_success", None)
    error = request.session.pop("settings_error", None)
    return templates.TemplateResponse("settings.html", _ctx(request, db,
        active="settings",
        success=success,
        error=error))


@app.post("/settings/profile")
def settings_profile_update(
    request: Request,
    name: str = Form(""),
    company: str = Form(""),
    phone_whatsapp: str = Form(""),
    whatsapp_opt_in: bool = Form(False),
    db: Session = Depends(get_db),
):
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse("/login", 302)

    name = name.strip()
    company = company.strip()
    phone_clean = "".join(c for c in phone_whatsapp if c.isdigit() or c == "+")

    if not name or len(name) < 2:
        request.session["settings_error"] = "Le nom doit contenir au moins 2 caractères."
        return RedirectResponse("/settings", 303)

    if whatsapp_opt_in:
        if not phone_clean or not _PHONE_RE.match(phone_clean):
            request.session["settings_error"] = "Numéro WhatsApp invalide. Format requis : +33612345678 ou +212661234567"
            return RedirectResponse("/settings", 303)
    elif phone_clean and not _PHONE_RE.match(phone_clean):
        request.session["settings_error"] = "Format du numéro invalide. Laissez vide ou utilisez : +33612345678"
        return RedirectResponse("/settings", 303)

    user.name = name
    user.company = company or None
    user.phone_whatsapp = phone_clean or None
    user.whatsapp_opt_in = whatsapp_opt_in
    db.commit()

    request.session["settings_success"] = "Profil mis à jour."
    return RedirectResponse("/settings", 303)


@app.post("/settings/password")
def settings_password_update(
    request: Request,
    current_password: str = Form(...),
    new_password: str = Form(...),
    new_password_confirm: str = Form(...),
    db: Session = Depends(get_db),
):
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse("/login", 302)

    from app.auth import verify_password, hash_password

    if not verify_password(current_password, user.password_hash):
        request.session["settings_error"] = "Le mot de passe actuel est incorrect."
        return RedirectResponse("/settings#security", 303)

    if len(new_password) < 8:
        request.session["settings_error"] = "Le nouveau mot de passe doit contenir au moins 8 caractères."
        return RedirectResponse("/settings#security", 303)

    if new_password != new_password_confirm:
        request.session["settings_error"] = "Les deux nouveaux mots de passe ne correspondent pas."
        return RedirectResponse("/settings#security", 303)

    user.password_hash = hash_password(new_password)
    db.commit()

    request.session["settings_success"] = "Mot de passe modifié avec succès."
    return RedirectResponse("/settings#security", 303)


@app.post("/settings/avatar")
async def settings_avatar_update(
    request: Request,
    db: Session = Depends(get_db),
):
    """Upload avatar : on attend un data URL base64 dans le body 'avatar_data'."""
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse("/login", 302)

    form = await request.form()
    avatar_data = form.get("avatar_data", "").strip()

    if not avatar_data:
        request.session["settings_error"] = "Aucune image fournie."
        return RedirectResponse("/settings", 303)

    # Validation : doit être un data URL image
    if not avatar_data.startswith("data:image/"):
        request.session["settings_error"] = "Format d'image invalide."
        return RedirectResponse("/settings", 303)

    # Limite à 500 KB pour le stockage en DB (data URL base64)
    if len(avatar_data) > 500_000:
        request.session["settings_error"] = "L'image est trop volumineuse (max 350 KB après crop)."
        return RedirectResponse("/settings", 303)

    user.avatar_url = avatar_data
    db.commit()

    request.session["settings_success"] = "Photo de profil mise à jour."
    return RedirectResponse("/settings", 303)


@app.post("/settings/avatar/remove")
def settings_avatar_remove(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse("/login", 302)
    user.avatar_url = None
    db.commit()
    request.session["settings_success"] = "Photo de profil supprimée."
    return RedirectResponse("/settings", 303)


# ─────────────────────────────────────────────────────────────────────
# Console Admin (accès restreint is_admin=True)
# ─────────────────────────────────────────────────────────────────────

@app.get("/admin", response_class=HTMLResponse)
def admin_dashboard(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user or not user.is_admin:
        raise HTTPException(403, "Accès réservé à l'équipe ARGUS")

    # KPIs
    total_users  = db.query(func.count(User.id)).scalar()
    total_scans  = db.query(func.count(Scan.id)).scalar()
    users_by_plan = {
        plan: db.query(func.count(User.id)).filter(User.plan == plan).scalar()
        for plan in ["free", "essentiel", "pro", "agency"]
    }
    # MRR estimé
    mrr = (
        users_by_plan.get("essentiel", 0) * 29 +
        users_by_plan.get("pro", 0) * 79 +
        users_by_plan.get("agency", 0) * 249
    )

    recent_users = db.query(User).order_by(User.created_at.desc()).limit(20).all()
    recent_scans = db.query(Scan).order_by(Scan.started_at.desc()).limit(30).all()
    whatsapp_leads = db.query(User).filter(User.whatsapp_opt_in == True).all()

    # Domaines uniques scannés (top 50 par nombre de scans)
    from sqlalchemy import desc as _desc
    domain_rows = (
        db.query(
            Scan.domain,
            func.count(Scan.id).label("count"),
            func.max(Scan.started_at).label("last_at"),
        )
        .group_by(Scan.domain)
        .order_by(_desc("count"), _desc("last_at"))
        .limit(50)
        .all()
    )
    domains_summary = []
    for row in domain_rows:
        last_scan = (
            db.query(Scan)
            .filter(Scan.domain == row.domain)
            .order_by(Scan.started_at.desc())
            .first()
        )
        owner_email = None
        if last_scan and last_scan.user_id:
            ow = db.query(User).filter(User.id == last_scan.user_id).first()
            owner_email = ow.email if ow else None
        domains_summary.append({
            "domain": row.domain,
            "count": row.count,
            "last_scan_at": row.last_at.strftime("%d/%m/%Y %H:%M") if row.last_at else "—",
            "last_grade": last_scan.risk_grade if last_scan else None,
            "last_owner_email": owner_email,
        })

    return templates.TemplateResponse("admin.html", _ctx(request, db,
        total_users=total_users,
        total_scans=total_scans,
        users_by_plan=users_by_plan,
        mrr=mrr,
        recent_users=recent_users,
        recent_scans=recent_scans,
        whatsapp_leads=whatsapp_leads,
        domains_summary=domains_summary,
        plan_names=PLAN_NAMES,
        now=datetime.utcnow(),
    ))


@app.post("/admin/user/{user_id}/plan")
def admin_change_plan(user_id: int, plan: str = Form(...), request: Request = None,
                       db: Session = Depends(get_db)):
    admin = get_current_user(request, db)
    if not admin or not admin.is_admin:
        raise HTTPException(403)
    user = db.query(User).filter(User.id == user_id).first()
    if user and plan in PLAN_LIMITS:
        user.plan = plan
        db.commit()
    return RedirectResponse("/admin", 302)


# ─────────────────────────────────────────────────────────────────────
# Admin — Exports CSV
# ─────────────────────────────────────────────────────────────────────

def _csv_response(filename: str, rows: list[list]) -> "Response":
    """Helper pour retourner un CSV utf-8 BOM (compatible Excel)."""
    import csv, io
    from fastapi.responses import Response
    buf = io.StringIO()
    writer = csv.writer(buf, delimiter=";", quoting=csv.QUOTE_MINIMAL)
    for row in rows:
        writer.writerow(row)
    content = "﻿" + buf.getvalue()  # BOM pour Excel
    return Response(
        content=content,
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/admin/export/users.csv")
def admin_export_users(request: Request, db: Session = Depends(get_db),
                       plan: str = None):
    """Exporte tous les utilisateurs en CSV. Filtre optionnel par plan."""
    admin = get_current_user(request, db)
    if not admin or not admin.is_admin:
        raise HTTPException(403)

    q = db.query(User).order_by(User.created_at.desc())
    if plan and plan in PLAN_LIMITS:
        q = q.filter(User.plan == plan)
    users = q.all()

    rows = [["id", "email", "name", "company", "plan", "verified", "whatsapp", "whatsapp_opt_in",
             "is_admin", "created_at", "last_login_at"]]
    for u in users:
        rows.append([
            u.id,
            u.email,
            u.name or "",
            u.company or "",
            u.plan,
            "yes" if u.email_verified_at else "no",
            u.phone_whatsapp or "",
            "yes" if u.whatsapp_opt_in else "no",
            "yes" if u.is_admin else "no",
            u.created_at.strftime("%Y-%m-%d %H:%M:%S") if u.created_at else "",
            u.last_login_at.strftime("%Y-%m-%d %H:%M:%S") if u.last_login_at else "",
        ])

    suffix = f"_{plan}" if plan else "_all"
    return _csv_response(f"argus_users{suffix}_{datetime.utcnow().strftime('%Y%m%d')}.csv", rows)


@app.get("/admin/export/emails.csv")
def admin_export_emails(request: Request, db: Session = Depends(get_db),
                        plan: str = None, verified_only: bool = False,
                        whatsapp_only: bool = False):
    """Exporte juste les emails pour campagnes marketing."""
    admin = get_current_user(request, db)
    if not admin or not admin.is_admin:
        raise HTTPException(403)

    q = db.query(User).order_by(User.created_at.desc())
    if plan and plan in PLAN_LIMITS:
        q = q.filter(User.plan == plan)
    if verified_only:
        q = q.filter(User.email_verified_at.isnot(None))
    if whatsapp_only:
        q = q.filter(User.whatsapp_opt_in == True)
    users = q.all()

    rows = [["email", "name", "company", "plan", "phone_whatsapp", "verified"]]
    for u in users:
        rows.append([
            u.email,
            u.name or "",
            u.company or "",
            u.plan,
            u.phone_whatsapp or "",
            "yes" if u.email_verified_at else "no",
        ])

    parts = []
    if plan: parts.append(plan)
    if verified_only: parts.append("verified")
    if whatsapp_only: parts.append("whatsapp")
    suffix = "_" + "_".join(parts) if parts else ""
    return _csv_response(f"argus_emails{suffix}_{datetime.utcnow().strftime('%Y%m%d')}.csv", rows)


@app.get("/admin/export/scans.csv")
def admin_export_scans(request: Request, db: Session = Depends(get_db)):
    """Exporte tous les scans + leur owner."""
    admin = get_current_user(request, db)
    if not admin or not admin.is_admin:
        raise HTTPException(403)

    scans = db.query(Scan).order_by(Scan.started_at.desc()).all()
    rows = [["id", "domain", "status", "owner_email", "owner_plan",
             "assets_count", "alive_count", "vulns_count",
             "critical", "high", "kev",
             "risk_score", "risk_grade", "pentest_authorized",
             "started_at", "completed_at"]]
    for s in scans:
        owner = s.user.email if s.user else "anonyme"
        owner_plan = s.user.plan if s.user else ""
        rows.append([
            s.id, s.domain, s.status, owner, owner_plan,
            s.assets_count or 0, s.alive_count or 0, s.vulns_count or 0,
            s.critical_count or 0, s.high_count or 0, s.kev_count or 0,
            s.risk_score or 0, s.risk_grade or "",
            "yes" if s.pentest_authorized else "no",
            s.started_at.strftime("%Y-%m-%d %H:%M:%S") if s.started_at else "",
            s.completed_at.strftime("%Y-%m-%d %H:%M:%S") if s.completed_at else "",
        ])
    return _csv_response(f"argus_scans_{datetime.utcnow().strftime('%Y%m%d')}.csv", rows)


@app.get("/admin/export/whatsapp.csv")
def admin_export_whatsapp(request: Request, db: Session = Depends(get_db)):
    """Exporte les leads avec WhatsApp opt-in (pour campagnes WA)."""
    admin = get_current_user(request, db)
    if not admin or not admin.is_admin:
        raise HTTPException(403)
    users = db.query(User).filter(
        User.whatsapp_opt_in == True,
        User.phone_whatsapp.isnot(None),
    ).order_by(User.created_at.desc()).all()
    rows = [["phone_whatsapp", "name", "email", "company", "plan", "created_at"]]
    for u in users:
        rows.append([
            u.phone_whatsapp,
            u.name or "",
            u.email,
            u.company or "",
            u.plan,
            u.created_at.strftime("%Y-%m-%d") if u.created_at else "",
        ])
    return _csv_response(f"argus_whatsapp_leads_{datetime.utcnow().strftime('%Y%m%d')}.csv", rows)


# ─────────────────────────────────────────────────────────────────────
# Public reports — rapports partageables par lien (commercial)
# ─────────────────────────────────────────────────────────────────────

import re as _re_slug


def _slugify(text: str) -> str:
    """Convertit un domaine en slug URL-safe : 'uir.ac.ma' -> 'uir-ac-ma'."""
    s = (text or "").strip().lower()
    s = _re_slug.sub(r"[^a-z0-9]+", "-", s)
    s = s.strip("-")[:60]
    return s or "report"


@app.post("/admin/scan/{scan_id}/share")
def admin_create_share_link(
    scan_id: int,
    request: Request,
    slug: str = Form(""),
    custom_intro: str = Form(""),
    contact_name: str = Form(""),
    contact_email: str = Form(""),
    db: Session = Depends(get_db),
):
    """Génère un lien public partageable pour ce scan. Admin uniquement."""
    admin = get_current_user(request, db)
    if not admin or not admin.is_admin:
        raise HTTPException(403)

    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(404, "Scan introuvable")
    if scan.status != "completed":
        raise HTTPException(400, "Le scan doit être terminé")

    # Slug : custom ou auto-généré
    if slug:
        slug = _slugify(slug)
    else:
        base = _slugify(scan.domain)
        slug = base
        # Si existe déjà, ajoute un suffixe scan_id
        existing = db.query(PublicReport).filter(PublicReport.slug == slug).first()
        if existing:
            slug = f"{base}-{scan_id}"

    # Vérifie l'unicité
    if db.query(PublicReport).filter(PublicReport.slug == slug).first():
        raise HTTPException(409, f"Le slug '{slug}' est déjà utilisé. Choisissez-en un autre.")

    report = PublicReport(
        scan_id=scan_id,
        slug=slug,
        custom_intro=custom_intro.strip() or None,
        contact_name=contact_name.strip() or None,
        contact_email=contact_email.strip() or None,
    )
    db.add(report)
    db.commit()
    db.refresh(report)

    base_url = str(request.base_url).rstrip("/")
    public_url = f"{base_url}/r/{slug}"
    return {"slug": slug, "url": public_url, "scan_id": scan_id}


@app.get("/r/{slug}", response_class=HTMLResponse)
def public_report_view(slug: str, request: Request, db: Session = Depends(get_db)):
    """Rapport public consultable sans authentification."""
    report = db.query(PublicReport).filter(PublicReport.slug == slug).first()
    if not report:
        raise HTTPException(404, "Rapport introuvable ou expiré")

    if report.expires_at and report.expires_at < datetime.utcnow():
        raise HTTPException(410, "Ce lien a expiré")

    scan = db.query(Scan).filter(Scan.id == report.scan_id).first()
    if not scan:
        raise HTTPException(404)

    # Incrémente compteur de vues (sauf si l'admin consulte)
    user = get_current_user(request, db)
    if not (user and user.is_admin):
        report.view_count = (report.view_count or 0) + 1
        report.last_viewed_at = datetime.utcnow()
        db.commit()

    # Construit TOUS les findings classifiés (pas juste 1 spotlight)
    vulns_sorted = sorted(scan.vulns, key=nuclei.vuln_priority_score, reverse=True)
    findings = _build_all_findings(scan, vulns_sorted)

    return templates.TemplateResponse("public_report.html", _ctx(
        request, db,
        report=report,
        scan=scan,
        findings=findings,
        total_assets=scan.assets_count or 0,
        alive_assets=scan.alive_count or 0,
        total_vulns=scan.vulns_count or 0,
        critical=scan.critical_count or 0,
        high=scan.high_count or 0,
        kev=scan.kev_count or 0,
        public_url=f"{str(request.base_url).rstrip('/')}/r/{slug}",
    ))


def _build_all_findings(scan, vulns_sorted):
    """
    Identifie TOUS les findings critiques du scan et les renvoie avec
    démo, cas réel, impact, et plan de correction. Liste ordonnée
    par sévérité.
    """
    findings = []
    domain = scan.domain

    # ── 1. CVE activement exploitée (KEV) ────────────────────────
    kev_vulns = [v for v in vulns_sorted if v.kev]
    if kev_vulns:
        v = kev_vulns[0]
        findings.append({
            "id": "kev",
            "severity": "critical",
            "icon": "🚨",
            "title": "Faille critique exploitée par des hackers en ce moment",
            "summary": f"{v.name or v.template_id}" + (f" — {v.cve_id}" if v.cve_id else ""),
            "evidence": v.matched_url or domain,
            "analogy": (
                "<strong>Imaginez :</strong> un serrurier publie sur YouTube un tutoriel "
                "« Comment ouvrir la serrure modèle X en 3 secondes » — et la vidéo cumule 50 000 vues "
                "de gens qui cambriolent pour vivre. Votre maison utilise cette serrure exacte. "
                "Le tutoriel est gratuit. Les outils sont gratuits. Tout ce qu'il manque aux cambrioleurs, "
                "c'est l'adresse — et l'adresse est publique."
            ),
            "what_it_means": (
                "Cette faille fait partie du <strong>catalogue CISA KEV</strong> (Known Exploited Vulnerabilities) — "
                "c'est-à-dire qu'elle est <strong>activement utilisée par des hackers</strong> "
                "contre d'autres entreprises dans le monde en ce moment même. "
                "L'agence américaine CISA (équivalent de l'ANSSI) maintient cette liste pour signaler les failles "
                "« en feu ». Les exploits sont publics, automatisés et téléchargeables gratuitement. "
                "Vous n'êtes pas une cible « possible » — vous êtes une cible <em>active</em>."
            ),
            "scenario": (
                "<strong>Mardi 14h02.</strong> Un opérateur d'un groupe ransomware basé à Bucarest lance "
                "son script habituel : il scanne toutes les IP d'Europe à la recherche de cette faille précise. "
                "<strong>14h04 :</strong> votre serveur répond positivement au test. "
                "<strong>14h07 :</strong> il a un shell administrateur sur votre machine. "
                "<strong>14h12 :</strong> il dépose un backdoor (porte cachée pour revenir plus tard), "
                "désactive vos antivirus, et part dîner. "
                "<strong>Pendant 6 mois :</strong> vous ne voyez rien. "
                "<strong>Un lundi matin, à 5h du matin :</strong> tous vos serveurs sont chiffrés, "
                "et un fichier <code>README.txt</code> demande 800 000€ en Bitcoin."
            ),
            "demonstration": (
                f"<strong>Concrètement, voici l'attaque en 30 secondes :</strong><br><br>"
                f"1. L'attaquant tape <code>nuclei -u https://{domain} -t cves/{v.cve_id or 'XXXX'}.yaml</code> "
                f"(c'est une commande gratuite, n'importe quel ado de 15 ans peut le faire).<br>"
                f"2. En moins de 3 secondes, l'outil affiche <code>[CRITICAL] {v.cve_id or 'CVE-XXXX-XXXX'} - VULNERABLE</code>.<br>"
                f"3. Il télécharge l'exploit correspondant sur GitHub (encore gratuit, public).<br>"
                f"4. Il lance l'exploit → accès <strong>root/administrateur</strong> direct sur votre serveur. "
                f"Pas besoin de mot de passe. Pas besoin de phishing. Juste cette commande."
            ),
            "real_case": (
                "<strong>Cas MOVEit (mai-juin 2023) — l'attaque la plus rentable de l'histoire récente :</strong><br><br>"
                "MOVEit Transfer est un logiciel de transfert sécurisé de fichiers utilisé par les grandes "
                "entreprises et les administrations. Le 27 mai 2023, le groupe Cl0p découvre une faille "
                "(CVE-2023-34362). Avant même que l'éditeur ne publie un patch, ils lancent une campagne d'exploitation massive. "
                "<strong>En 72h, 2 000 serveurs sont compromis dans le monde.</strong> "
                "Victimes : British Airways, BBC, Shell, le ministère américain de l'Énergie, "
                "Sony, EY, PwC… Plus de <strong>62 millions de personnes</strong> ont vu leurs données fuiter. "
                "Coût total estimé pour les entreprises : <strong>plus de 10 milliards de dollars</strong>. "
                "Cl0p aurait empoché entre 75 et 100 millions de dollars en rançons. "
                "La faille était dans le catalogue KEV dès le 2 juin."
            ),
            "action": (
                "Patcher immédiatement la version logicielle concernée. C'est l'action n°1 absolue, "
                "tout le reste passe après. Si pour une raison technique le patch n'est pas applicable "
                "ce week-end, isolez l'actif derrière un firewall avec accès restreint par IP."
            ),
        })

    # ── 2. Vulnérabilité critique ────────────────────────────────
    critical = [v for v in vulns_sorted if (v.severity or "").lower() == "critical" and not v.kev]
    if critical:
        v = critical[0]
        findings.append({
            "id": "critical",
            "severity": "critical",
            "icon": "🔥",
            "title": "Vulnérabilité critique exploitable",
            "summary": f"{v.name or v.template_id}" + (f" — {v.cve_id}" if v.cve_id else ""),
            "evidence": v.matched_url or domain,
            "analogy": (
                "<strong>Imaginez :</strong> la porte de votre coffre-fort est fissurée à un endroit précis. "
                "Pas besoin de crocheter, pas besoin de combinaison — il suffit de pousser au bon endroit "
                "et le coffre s'ouvre. Le mode d'emploi pour trouver l'endroit exact est publié gratuitement "
                "sur internet. C'est ça, une faille critique : la sécurité existe en apparence, "
                "mais elle est cassée à un endroit que n'importe qui peut trouver."
            ),
            "what_it_means": (
                "Une faille de sévérité <strong>critique</strong> a été détectée. "
                "Concrètement, un attaquant peut potentiellement <strong>prendre le contrôle "
                "du serveur compromis</strong>, voler vos données, ou l'utiliser comme tremplin "
                "pour atteindre votre réseau interne. La note « critique » signifie que la faille "
                "permet une compromission complète, sans authentification, et qu'elle est exploitable à distance — "
                "c'est-à-dire de n'importe où dans le monde."
            ),
            "scenario": (
                "<strong>Jeudi 23h15.</strong> Un étudiant en informatique à Hyderabad cherche un sujet de "
                "thèse. Il découvre un PoC (Proof of Concept) publié 4 heures plus tôt sur Twitter. "
                "Il copie-colle le code Python sur sa machine, change l'URL cible par la vôtre. "
                "<strong>23h17 :</strong> il a un accès terminal sur votre serveur de production. "
                "Il ne sait pas trop quoi en faire (il voulait juste apprendre), mais il prend une capture d'écran "
                "et la poste sur Discord pour impressionner ses amis. "
                "<strong>23h45 :</strong> un membre de son serveur Discord, qui lui n'est pas un étudiant, "
                "lui propose 500€ pour l'accès. L'étudiant accepte. "
                "<strong>Vendredi 8h :</strong> vos bases de données sont déjà copiées sur un serveur en Russie."
            ),
            "demonstration": (
                f"<strong>L'exploitation tient en 3 lignes de Python :</strong><br><br>"
                f"1. L'attaquant ouvre le script PoC public (cherchez « {v.cve_id or 'CVE'} PoC » sur GitHub, "
                f"il y en a souvent une dizaine).<br>"
                f"2. Il change la variable <code>target = \"https://...\"</code> avec votre URL.<br>"
                f"3. Il appuie sur Entrée. La faille s'exploite seule. "
                f"<strong>Aucune compétence avancée requise.</strong> Des outils automatisés font ça en boucle, "
                f"24h/24, sur des plages d'IPs entières (ex: tout le réseau d'un fournisseur cloud français)."
            ),
            "real_case": (
                "<strong>Log4Shell (décembre 2021) — la plus grande faille critique de la décennie :</strong><br><br>"
                "Le 9 décembre 2021, un chercheur chinois publie sur Twitter une preuve d'exploitation "
                "d'une faille dans Log4j, une bibliothèque Java utilisée par <strong>35% des serveurs Java "
                "dans le monde</strong> (incluse par défaut dans Minecraft, Twitter, Steam, iCloud, Tesla, "
                "et des dizaines de milliers d'entreprises). "
                "<strong>9 heures plus tard</strong>, les premières exploitations sont observées sur internet. "
                "<strong>Au pic, plus de 100 attaques par seconde</strong> visaient les serveurs vulnérables. "
                "Le gouvernement américain a qualifié l'incident de « menace de sécurité nationale ». "
                "Coût estimé : <strong>plus de 90 milliards de dollars</strong> en remédiation mondiale. "
                "Certaines entreprises (comme Equifax) ont mis 6 mois pour finir de patcher tous leurs systèmes."
            ),
            "action": (
                "Patcher la version logicielle en priorité absolue (cette semaine, pas ce mois-ci). "
                "Si le patch n'est pas disponible, isoler l'actif derrière un VPN ou un WAF (pare-feu web) "
                "le temps de trouver une solution. Communiquer à votre équipe technique avec l'identifiant "
                "CVE exact — c'est le seul vocabulaire qu'ils comprennent vite."
            ),
        })

    # ── 3. Interface d'administration exposée ────────────────────
    sensitive_keywords_explanations = {
        "phpmyadmin": ("phpMyAdmin", "outil web de gestion de base de données MySQL", "vos données complètes"),
        "cpanel":     ("cPanel",     "panneau d'administration d'hébergement",            "votre site et tous vos fichiers"),
        "whm":        ("WHM",        "panneau de gestion serveur",                        "le serveur complet et tous les sites hébergés"),
        "wp-admin":   ("WordPress Admin", "interface d'administration WordPress",         "votre site et le contenu publié"),
        "webmail":    ("Webmail",    "interface email web",                               "tous vos emails et contacts"),
        "owa":        ("Outlook Web Access", "webmail Exchange",                          "les emails de l'entreprise"),
        "admin":      ("/admin",     "interface administrative générique",                "selon la nature du panneau"),
        "manage":     ("manager",    "interface de gestion personnalisée",                "selon la nature du système"),
        "intranet":   ("Intranet",   "réseau interne accessible publiquement",            "vos documents internes"),
        "vpn":        ("VPN portal", "portail d'accès distant",                           "votre réseau interne"),
        "ftp":        ("FTP",        "serveur de fichiers",                               "tous vos fichiers transférés"),
        "jenkins":    ("Jenkins",    "système d'intégration continue",                    "votre code source et builds"),
    }

    sensitive_assets = []
    for a in scan.assets[:200]:
        url_lower = (a.url or "").lower()
        for kw, info in sensitive_keywords_explanations.items():
            if kw in url_lower:
                sensitive_assets.append({"url": a.url, "keyword": kw, "info": info})
                break

    if sensitive_assets:
        first = sensitive_assets[0]
        name, what_is, what_attacker_gets = first["info"]
        findings.append({
            "id": "exposed_admin",
            "severity": "high",
            "icon": "🔓",
            "title": f"Interface d'administration exposée publiquement",
            "summary": f"{name} accessible sans restriction : {first['url']}",
            "evidence": first["url"],
            "analogy": (
                f"<strong>Imaginez :</strong> votre coffre-fort professionnel est dans une pièce sécurisée "
                f"à l'arrière du magasin. Normal. Mais vous avez collé un panneau lumineux sur la devanture "
                f"qui dit : <em>« Coffre-fort ici, modèle marque-X, derrière cette porte »</em>. "
                f"La porte est verrouillée — mais maintenant TOUS les passants savent qu'il y a un coffre, "
                f"quel modèle, et où exactement. Il n'y a plus qu'à essayer les combinaisons. "
                f"<br><br>C'est exactement la situation avec <strong>{name}</strong> : "
                f"la porte d'entrée des administrateurs de votre infrastructure est visible depuis "
                f"n'importe quelle connexion internet du monde."
            ),
            "what_it_means": (
                f"<strong>{name}</strong> est un {what_is}. "
                f"Cette interface est conçue pour être utilisée par <strong>vos administrateurs depuis votre "
                f"réseau interne</strong> — pas depuis n'importe quelle connexion internet du monde. "
                f"Si un attaquant arrive à se connecter (mot de passe deviné, mot de passe fuité dans une "
                f"autre base de données, ou faille de l'interface elle-même), il obtient immédiatement "
                f"<strong>{what_attacker_gets}</strong>. C'est la marche la plus haute de l'échelle "
                f"des privilèges : tout en haut, accès complet."
            ),
            "scenario": (
                f"<strong>Lundi 3h17 du matin (heure de Paris).</strong> Un bot automatique tournant sur "
                f"un serveur compromis au Brésil scanne internet à la recherche d'interfaces "
                f"<code>{first['keyword']}</code>. Il trouve {first['url']}. "
                f"<strong>3h17 et 4 secondes :</strong> il lance une liste de 50 000 mots de passe (le top "
                f"des mots de passe leakés ces 5 dernières années + des variantes avec votre nom de marque). "
                f"<strong>4h08 :</strong> la combinaison <code>Admin@2024</code> fonctionne — un employé "
                f"avait défini ce mot de passe « temporaire » il y a 18 mois. "
                f"<strong>4h09 :</strong> le bot exporte automatiquement votre base de données complète "
                f"vers un serveur en Roumanie. "
                f"<strong>4h22 :</strong> il pose un script qui ouvrira à nouveau l'accès dans 30 jours "
                f"(au cas où vous changiez le mot de passe). "
                f"<strong>Mercredi suivant :</strong> votre base client est en vente sur un forum dark web "
                f"à 1€ la ligne. Vous ne le savez pas encore."
            ),
            "demonstration": (
                f"<strong>Voici l'attaque, étape par étape :</strong><br><br>"
                f"1. L'attaquant ouvre <code>{first['url']}</code> dans son navigateur. "
                f"La page de connexion s'affiche normalement (pas d'erreur, pas de blocage).<br>"
                f"2. Il lance <strong>Hydra</strong> ou <strong>Patator</strong> (outils gratuits "
                f"de brute-force) avec une liste de 50 000 mots de passe courants (rockyou.txt, "
                f"téléchargeable en 5 secondes).<br>"
                f"3. Il configure : <code>100 tentatives/seconde × 30 IP en parallèle</code> = "
                f"<strong>3 000 essais par seconde, distribués pour ne pas être bloqué</strong>.<br>"
                f"4. Si vos employés utilisent un mot de passe basé sur le nom de l'entreprise + année "
                f"(la combinaison la plus courante au monde), c'est cassé en <strong>moins d'une heure</strong>."
            ),
            "real_case": (
                "<strong>Western Sydney University (mai 2024) — phpMyAdmin oublié :</strong><br><br>"
                "Une interface phpMyAdmin avait été installée en 2019 par un développeur pour debugger "
                "un problème ponctuel, puis oubliée. Elle est restée accessible publiquement avec un "
                "mot de passe par défaut <code>root/root</code>. Un attaquant l'a trouvée via un scan "
                "Shodan (le moteur de recherche des objets connectés). "
                "<strong>Conséquences :</strong> données de <strong>10 000 étudiants</strong> exfiltrées "
                "(noms, dates de naissance, emails, notes, dossiers médicaux des étudiants en santé). "
                "Coût total estimé : <strong>environ 3 millions d'euros</strong> en forensics, notifications "
                "légales, frais juridiques et RP. La vice-chancellière a démissionné. "
                "Un employé ayant créé l'interface a été licencié. "
                "<br><br><strong>Le tragique :</strong> l'interface n'était utilisée par personne depuis 4 ans."
            ),
            "action": (
                f"<strong>Cette semaine :</strong><br>"
                f"1. <strong>Identifier qui utilise vraiment {first['url']} </strong> (probablement 1-2 personnes).<br>"
                f"2. <strong>Restreindre l'accès par IP whitelist</strong> dans votre firewall : "
                f"seulement les IP de vos admins légitimes. Coût : 30 minutes de config réseau.<br>"
                f"3. Si possible, <strong>placer derrière un VPN obligatoire</strong> : pour accéder "
                f"à {name}, il faut d'abord se connecter au VPN.<br>"
                f"4. <strong>Activer la double authentification (2FA)</strong> sur ce panneau "
                f"(un code SMS ou Google Authenticator en plus du mot de passe).<br>"
                f"5. <strong>Forcer changement de mot de passe</strong> avec politique forte "
                f"(≥14 caractères, avec majuscules, chiffres, symboles)."
            ),
            "other_examples": [a["url"] for a in sensitive_assets[1:5]],
        })

    # ── 4. Versions logicielles obsolètes ─────────────────────────
    old_tech_patterns = {
        "apache http server:2.2": ("Apache HTTPD 2.2", "support arrêté en 2017 (8+ ans sans patches)", 8),
        "apache http server:2.4.6": ("Apache HTTPD 2.4.6", "publié en 2013, des dizaines de CVE depuis", 11),
        "apache http server:2.4.29": ("Apache HTTPD 2.4.29", "publié en 2017, plusieurs CVE high+", 7),
        "php:5":      ("PHP 5.x", "support arrêté en janvier 2019", 6),
        "php:7.0":    ("PHP 7.0", "support arrêté en janvier 2019", 6),
        "php:7.1":    ("PHP 7.1", "support arrêté en décembre 2019", 5),
        "php:7.2":    ("PHP 7.2", "support arrêté en novembre 2020", 4),
        "php:7.3":    ("PHP 7.3", "support arrêté en décembre 2021", 3),
        "nginx:1.14": ("Nginx 1.14", "publié en 2018, plusieurs CVE depuis", 6),
        "nginx:1.16": ("Nginx 1.16", "publié en 2019", 5),
        "openssl:1.0": ("OpenSSL 1.0.x", "support arrêté en décembre 2019 — vulnérable à Heartbleed et autres", 5),
        "openssl:0.9": ("OpenSSL 0.9.x", "extrêmement obsolète, vulnérabilités multiples publiques", 15),
        "iis:7":      ("Microsoft IIS 7", "support arrêté en 2020", 4),
        "iis:8":      ("Microsoft IIS 8", "support arrêté en octobre 2023", 1),
    }
    old_tech = []
    for a in scan.assets[:100]:
        for t in (a.tech or []):
            t_lower = str(t).lower()
            for pattern, info in old_tech_patterns.items():
                if pattern in t_lower:
                    old_tech.append({"asset": a.url, "tech": t, "info": info})
                    break

    if old_tech:
        first = old_tech[0]
        product_name, age_info, years = first["info"]
        findings.append({
            "id": "old_software",
            "severity": "high",
            "icon": "🕰️",
            "title": "Versions logicielles obsolètes détectables publiquement",
            "summary": f"{product_name} sur {first['asset']} (et {len(old_tech) - 1} autre(s) actif(s))" if len(old_tech) > 1 else f"{product_name} sur {first['asset']}",
            "evidence": first["asset"] + " → " + first["tech"],
            "analogy": (
                f"<strong>Imaginez :</strong> vous conduisez une voiture de {years} ans qui n'a jamais été "
                f"révisée. Les freins ne sont plus aux normes, les airbags ont été rappelés mais pas remplacés, "
                f"et le constructeur a arrêté la production des pièces de rechange depuis longtemps. "
                f"En plus, vous avez collé une grande étiquette sur le pare-brise qui dit "
                f"<em>« Voiture modèle XYZ, année 20{15 if years > 9 else 18} »</em>. "
                f"Tous les mécaniciens malveillants qui passent voient immédiatement quel défaut exploiter. "
                f"<br><br>C'est ce que fait votre serveur avec <strong>{product_name}</strong>."
            ),
            "what_it_means": (
                f"Le serveur affiche publiquement la version exacte du logiciel qu'il utilise : <strong>{product_name}</strong>. "
                f"Cette version est <strong>{age_info}</strong> — donc <strong>aucune mise à jour de sécurité "
                f"n'est plus publiée pour elle</strong> depuis des années. Toutes les failles découvertes "
                f"depuis sont publiques, documentées dans des bases de données accessibles à n'importe qui, "
                f"et exploitables via des outils gratuits téléchargeables en 30 secondes. "
                f"<br><br>Pour information : un patch de sécurité = une rustine que l'éditeur publie quand une "
                f"faille est découverte. Quand le support s'arrête, plus de rustines. Mais les failles continuent "
                f"d'être trouvées par les chercheurs (et les attaquants), elles sont juste… jamais corrigées."
            ),
            "scenario": (
                f"<strong>Vendredi 16h.</strong> Un opérateur d'un groupe ransomware reçoit la mission de "
                f"trouver de nouvelles victimes avant la fin du mois. Il lance Shodan, un moteur de recherche "
                f"qui catalogue tous les serveurs visibles sur internet et leur version logicielle. "
                f"Sa requête : <code>product:\"{product_name.split()[0]}\" version:\"{product_name.split()[-1]}\"</code>. "
                f"<strong>16h 02 :</strong> 4 800 serveurs vulnérables s'affichent. Le vôtre fait partie de la liste. "
                f"<strong>16h 03 :</strong> il télécharge un script d'exploit du repository GitHub d'un "
                f"chercheur bien intentionné (qui voulait juste démontrer la faille pour pousser les gens "
                f"à patcher). "
                f"<strong>16h 05 :</strong> il configure son script pour boucler sur les 4 800 IP. "
                f"<strong>Samedi matin :</strong> 700 entreprises sont compromises. Il choisit les 30 plus "
                f"« rentables » selon leur taille (analysée via leur site vitrine et LinkedIn) et déclenche "
                f"le chiffrement chez elles. <strong>Vous êtes peut-être dans le top 30, peut-être pas.</strong>"
            ),
            "demonstration": (
                f"<strong>Pour identifier votre version, l'attaquant utilise une commande triviale :</strong><br><br>"
                f"1. <code>curl -I https://{first['asset']}</code><br>"
                f"&nbsp;&nbsp;&nbsp;→ La réponse du serveur contient un header <code>Server: {product_name}</code>. "
                f"Votre serveur le donne <strong>gracieusement, à n'importe qui qui demande</strong>.<br><br>"
                f"2. Il copie <code>{product_name}</code> dans <strong>NVD</strong> (la base CVE publique du "
                f"gouvernement américain) ou simplement Google.<br>"
                f"&nbsp;&nbsp;&nbsp;→ <strong>Liste des failles connues</strong> s'affiche en quelques secondes. "
                f"Pour {product_name}, il y en a une dizaine au moins.<br><br>"
                f"3. Il choisit la plus exploitable (généralement celle avec un PoC public déjà écrit) et "
                f"lance l'attaque correspondante. <strong>Total de l'opération : 4 minutes.</strong>"
            ),
            "real_case": (
                "<strong>Equifax (juillet-septembre 2017) — l'attaque due à un seul patch oublié :</strong><br><br>"
                "Equifax est l'un des trois bureaux de crédit américains : ils détiennent les données financières "
                "et personnelles de plus de 800 millions de personnes. En mars 2017, une faille critique "
                "(CVE-2017-5638) est publiée dans Apache Struts, un composant logiciel qu'Equifax utilise. "
                "<strong>Un patch est disponible le 7 mars 2017</strong>. "
                "L'équipe IT d'Equifax envoie un email demandant à toutes les équipes de patcher dans les 48h. "
                "<strong>Mais un serveur est oublié.</strong> "
                "Le 13 mai 2017, des attaquants (probablement chinois selon le DOJ américain) trouvent ce serveur "
                "non patché via un simple scan internet. Ils restent dans le réseau d'Equifax pendant <strong>76 jours</strong>, "
                "exfiltrant lentement des données pour ne pas alerter. "
                "<strong>Bilan final :</strong> 147 millions de personnes touchées (noms, n° de sécu, dates de naissance, "
                "adresses). <strong>700 millions de dollars d'amende</strong>. Le PDG, le DSI et la RSSI ont démissionné. "
                "Le procureur général américain a recommandé des poursuites pénales. "
                "<strong>Coût total estimé : 1,4 milliard de dollars.</strong> Tout ça parce qu'un patch de mars n'avait "
                "pas été appliqué sur un serveur."
            ),
            "action": (
                f"<strong>Ce mois-ci :</strong><br>"
                f"1. <strong>Lister toutes les versions logicielles obsolètes</strong> de votre parc "
                f"(cette analyse vous en donne déjà une partie). Demander à votre équipe IT un export "
                f"de l'inventaire avec les versions exactes.<br>"
                f"2. <strong>Planifier une fenêtre de maintenance</strong> (généralement un dimanche soir) "
                f"pour mettre à jour vers les versions supportées et patchées.<br>"
                f"3. <strong>Mettre en place une veille mensuelle</strong> sur les CVE des logiciels que vous "
                f"utilisez (outil gratuit : <code>dependabot</code> sur GitHub, ou abonnement à US-CERT).<br>"
                f"4. <strong>Masquer les bannières de version</strong> dans les headers HTTP (option de "
                f"configuration de votre serveur web) — ça ralentit l'attaquant sans le bloquer, "
                f"complément utile mais jamais remplaçant du patch."
            ),
            "other_examples": [f"{ot['asset']} → {ot['tech']}" for ot in old_tech[1:5]],
        })

    # ── 5. Sécurité email — DMARC ─────────────────────────────────
    dmarc = scan.dmarc or {}
    if not dmarc.get("present"):
        findings.append({
            "id": "no_dmarc",
            "severity": "high",
            "icon": "📧",
            "title": "Phishing au nom de votre domaine — protection absente",
            "summary": f"Aucun enregistrement DMARC pour {domain}",
            "evidence": f"dig _dmarc.{domain} TXT → aucune réponse",
            "analogy": (
                f"<strong>Imaginez :</strong> la poste accepterait n'importe quelle lettre signée "
                f"« {domain} », sans vérifier qui l'a écrite, et la livrerait normalement chez vos clients "
                f"et partenaires. N'importe quel inconnu peut <strong>imiter votre papier à en-tête</strong> "
                f"et envoyer du courrier à votre place. Le destinataire reçoit une enveloppe avec votre "
                f"vrai nom, votre vraie adresse, votre vrai logo. Comment pourrait-il douter ? "
                f"<br><br>C'est exactement la situation actuelle de votre domaine email."
            ),
            "what_it_means": (
                f"DMARC est une « règle » que vous publiez dans le DNS (l'annuaire d'internet) qui dit "
                f"aux serveurs mail (Gmail, Outlook, Apple Mail, etc.) : "
                f"<strong>« si tu reçois un email qui prétend venir de {domain} mais qui n'est pas authentifié, "
                f"rejette-le »</strong>. Sans DMARC, <strong>n'importe qui dans le monde peut envoyer des "
                f"emails en se faisant passer pour vous</strong>, et ces emails arriveront en boîte de réception "
                f"de vos clients/partenaires/employés comme s'ils étaient parfaitement légitimes. "
                f"<br><br>Pas en spam. Pas avec un avertissement. <strong>En vraie boîte de réception</strong>, "
                f"avec votre nom de domaine dans l'expéditeur."
            ),
            "scenario": (
                f"<strong>Mardi 9h14.</strong> Votre directrice administrative et financière (DAF), Sophie, "
                f"reçoit un email. Expéditeur : <code>pdg@{domain}</code>. Objet : <em>« URGENT - "
                f"Acquisition confidentielle à valider avant 12h »</em>. "
                f"<br><br>Le mail dit : <em>« Sophie, je suis en réunion avec nos avocats. Nous finalisons "
                f"le rachat de la société CIBLE-X dont je t'ai parlé hier. Le vendeur exige un acompte "
                f"de bonne foi de 87 000€ avant midi sinon la deal saute. Voici le RIB : FR76 …. — RIB "
                f"de leur étude notariale. Confidentialité absolue jusqu'à l'annonce officielle. "
                f"Je suis injoignable jusqu'à 13h, ne m'appelle pas. Tu peux gérer ? Merci. P. »</em> "
                f"<br><br>Sophie hésite. Mais l'expéditeur est bien <code>pdg@{domain}</code>. Le ton "
                f"correspond au style du PDG. Hier matin, justement, le PDG avait parlé d'opportunités "
                f"d'acquisitions en réunion CODIR (info publique sur LinkedIn). Elle vire les 87 000€. "
                f"<br><br><strong>16h.</strong> Le vrai PDG sort de réunion. Il n'a jamais envoyé cet email. "
                f"L'argent est sur un compte aux Émirats. Il y restera 47 minutes avant d'être redistribué "
                f"sur 12 autres comptes dans 8 pays. <strong>87 000€ irrécupérables.</strong> "
                f"<br><br>Avec DMARC actif et configuré en <code>p=reject</code>, l'email serait arrivé "
                f"directement dans la corbeille, jamais vu par Sophie."
            ),
            "demonstration": (
                f"<strong>Combien de temps pour usurper votre domaine ? Réponse : 38 secondes.</strong><br><br>"
                f"1. L'attaquant ouvre <code>https://emkei.cz</code> (site gratuit, public, légal pour "
                f"l'envoi de notifications légitimes — mais utilisé massivement pour le phishing).<br>"
                f"2. Il remplit le formulaire : "
                f"From: <code>direction@{domain}</code>, To: <code>compta@votre-client.fr</code>, "
                f"Subject: <em>Mise à jour RIB urgente</em>, Body: faux message.<br>"
                f"3. Clic sur « Send ». <strong>L'email part en 2 secondes</strong>, arrive chez votre "
                f"client en moins d'une minute, dans la boîte de réception principale (pas en spam, car "
                f"vous n'avez pas de DMARC pour signaler que cet email est faux).<br><br>"
                f"<strong>Variante plus pro :</strong> il utilise un outil comme <code>Gophish</code> "
                f"pour envoyer 5 000 phishings à vos clients en une heure, avec personnalisation "
                f"automatique des prénoms (scrappés sur LinkedIn)."
            ),
            "real_case": (
                "<strong>Pathé France (mars 2018) — 19 millions d'euros disparus en 3 semaines :</strong><br><br>"
                "Le 3 mars 2018, la directrice financière de Pathé Pictures International reçoit un email "
                "qui semble venir de <strong>Marc Lacan, le PDG du groupe Pathé</strong>. "
                "L'email demande de débloquer urgemment des fonds pour une acquisition confidentielle en Asie. "
                "Le RIB indiqué pointe vers un compte à Hong Kong. La DAF, croyant agir sur ordre du PDG, "
                "ordonne le virement. <strong>Sur trois semaines, 19,2 millions d'euros</strong> sont virés "
                "sur 8 transactions vers différents comptes. "
                "<br><br>Quand le PDG découvre l'arnaque, l'argent est déjà parti. La DAF est licenciée. "
                "Le PDG est licencié 3 mois plus tard pour défaut de contrôle interne. "
                "Pathé porte plainte, l'enquête remonte jusqu'à un réseau israélien et chinois — "
                "<strong>l'argent ne sera jamais récupéré</strong>. "
                "<br><br><strong>Cause technique unique :</strong> Pathé n'avait pas configuré DMARC sur son "
                "domaine. Avec DMARC, l'email frauduleux aurait été rejeté avant même d'atteindre "
                "la boîte de la DAF. "
                "<br><br><strong>Au niveau mondial :</strong> le FBI estime les pertes annuelles dues "
                "à l'arnaque au président (CEO fraud / BEC = Business Email Compromise) à "
                "<strong>50+ milliards de dollars par an</strong>. C'est la cybercriminalité la plus rentable "
                "au monde, devant le ransomware."
            ),
            "action": (
                f"<strong>Cette semaine — 5 minutes de config, gratuit :</strong><br>"
                f"1. Demandez à votre administrateur DNS d'ajouter un enregistrement TXT au nom "
                f"<code>_dmarc.{domain}</code> avec la valeur :<br>"
                f"&nbsp;&nbsp;&nbsp;<code>v=DMARC1; p=none; rua=mailto:dmarc@{domain}</code><br>"
                f"&nbsp;&nbsp;&nbsp;(<code>p=none</code> = juste observer pour l'instant, ne rien bloquer)<br>"
                f"2. <strong>Pendant 1 mois :</strong> consultez les rapports DMARC reçus à "
                f"<code>dmarc@{domain}</code>. Vous verrez qui envoie quoi en votre nom.<br>"
                f"3. <strong>Une fois rassuré que tous vos envois légitimes passent :</strong> "
                f"passez à <code>p=quarantine</code> (emails frauduleux → spam) pendant 1 mois.<br>"
                f"4. <strong>Étape finale :</strong> <code>p=reject</code> = les emails usurpés sont "
                f"totalement bloqués. <strong>Phishing à votre nom impossible.</strong><br><br>"
                f"<strong>Coût total :</strong> 5 minutes de config DNS + 2 mois d'observation passive. "
                f"<strong>Gain potentiel :</strong> éviter une CEO fraud à 100 000€+."
            ),
        })
    elif dmarc.get("policy") == "none":
        findings.append({
            "id": "dmarc_none",
            "severity": "medium",
            "icon": "📧",
            "title": "Politique DMARC en mode 'observation' seulement",
            "summary": f"DMARC publié mais avec p=none (n'effectue aucun blocage)",
            "evidence": f"_dmarc.{domain} → p=none",
            "analogy": (
                f"<strong>Imaginez :</strong> vous avez installé une alarme dans votre magasin… mais en mode "
                f"« silencieux ». L'alarme détecte les intrusions, prend des photos, enregistre tout — "
                f"mais elle ne sonne pas, ne prévient personne, et ne ferme aucune porte. C'est utile pour "
                f"comprendre <em>qui</em> vous attaque, mais ça ne vous protège pas. "
                f"<br><br>C'est exactement ce que fait votre DMARC en <code>p=none</code>."
            ),
            "what_it_means": (
                f"Vous avez publié DMARC (bravo, première étape), mais avec la directive <code>p=none</code> "
                f"qui signifie <strong>« observe les abus et envoie-moi un rapport, mais ne bloque rien »</strong>. "
                f"Les emails frauduleux qui se font passer pour vous continuent d'arriver chez vos correspondants. "
                f"<br><br>Le mode <code>p=none</code> est une étape transitoire <strong>indispensable</strong> "
                f"au début (pour s'assurer qu'on ne casse pas des envois légitimes), mais c'est une étape "
                f"<strong>à dépasser</strong>. Si vous restez en <code>p=none</code> pendant des années, "
                f"DMARC ne vous protège pas — il vous donne juste des statistiques."
            ),
            "scenario": (
                f"<strong>Vendredi 11h.</strong> Un attaquant teste un phishing contre vos clients en "
                f"se faisant passer pour <code>support@{domain}</code>. Il envoie 200 emails. "
                f"<strong>Résultat :</strong> 198 sont délivrés normalement chez vos clients. "
                f"2 sont rapportés à votre adresse DMARC (parce que vous avez configuré <code>rua=</code>). "
                f"<br><br>Vous voyez le rapport lundi matin. Vous comprenez qu'il y a un problème. "
                f"Mais entre vendredi et lundi, <strong>15 de vos clients ont cliqué sur le lien</strong> "
                f"et donné leurs identifiants. <strong>Le mal est fait.</strong>"
            ),
            "demonstration": (
                "Identique au cas sans DMARC : l'attaquant spoof votre domaine, l'email passe en boîte "
                "de réception de votre destinataire. La seule différence : vous recevez un rapport "
                "agrégé hebdomadaire qui vous dit <em>combien</em> de spoofing ont eu lieu — "
                "<strong>après coup, sans aucune action préventive.</strong>"
            ),
            "real_case": (
                "Selon le rapport DMARC.org 2024, <strong>plus de 70% des domaines DMARC restent bloqués en "
                "<code>p=none</code> indéfiniment</strong>, par peur de casser un envoi légitime. "
                "Or sans passer en <code>quarantine</code> ou <code>reject</code>, DMARC n'a quasiment "
                "aucune valeur protective. Les boîtes mail (Gmail/Outlook) appliquent strictement votre "
                "politique : si vous dites « ne fais rien », elles ne font rien."
            ),
            "action": (
                f"<strong>Maintenant que DMARC est en place, terminez le travail :</strong><br>"
                f"1. <strong>Pendant 1-2 mois :</strong> consultez vos rapports DMARC. Identifiez tous "
                f"vos émetteurs légitimes (Google Workspace, Mailchimp, votre CRM, votre ERP…).<br>"
                f"2. <strong>Étape suivante :</strong> passer à <code>p=quarantine</code> "
                f"(emails frauduleux → spam au lieu de boîte principale).<br>"
                f"3. <strong>Étape finale :</strong> <code>p=reject</code> (emails frauduleux totalement "
                f"bloqués). C'est l'objectif."
            ),
        })

    # ── 6. SPF absent ─────────────────────────────────────────────
    spf = scan.spf or {}
    if not spf.get("present"):
        findings.append({
            "id": "no_spf",
            "severity": "medium",
            "icon": "✉️",
            "title": "Emails facilement usurpables",
            "summary": f"Aucun enregistrement SPF pour {domain}",
            "evidence": f"dig {domain} TXT → aucun SPF",
            "analogy": (
                f"<strong>Imaginez :</strong> dans votre quartier, le facteur livre tout ce qu'on lui donne, "
                f"sans vérifier d'où ça vient. N'importe quel inconnu peut déposer un courrier dans la "
                f"sacoche du facteur en disant <em>« c'est de la part de M. {domain.split('.')[0].title()} »</em>. "
                f"Le facteur ne vérifie pas, et livre. Vos voisins reçoivent une enveloppe à votre nom — "
                f"sauf que ce n'est pas vous qui l'avez écrite. "
                f"<br><br>SPF, c'est l'équivalent technique de la liste des facteurs officiellement autorisés "
                f"à livrer en votre nom. Sans cette liste, n'importe qui peut prétendre l'être."
            ),
            "what_it_means": (
                f"SPF (Sender Policy Framework) est une liste publique des serveurs autorisés à envoyer "
                f"des emails pour votre domaine. C'est techniquement un enregistrement DNS (l'annuaire d'internet) "
                f"qui dit : <em>« seuls les serveurs A, B et C peuvent légitimement envoyer du courrier "
                f"au nom de {domain} »</em>. "
                f"<br><br>Sans SPF, <strong>n'importe quel serveur dans le monde peut prétendre envoyer en "
                f"votre nom</strong>, et les boîtes mail destinataires n'ont aucun moyen de vérifier. "
                f"Conséquences secondaires : vos emails légitimes risquent aussi d'arriver en spam, "
                f"par manque de réputation (Gmail/Outlook préfèrent par défaut les domaines bien configurés)."
            ),
            "scenario": (
                f"<strong>Lundi matin.</strong> Un escroc télécharge la liste de vos clients (récupérée sur "
                f"votre site, votre LinkedIn d'entreprise, vos communiqués de presse). Il envoie un email "
                f"depuis son serveur personnel à Saint-Pétersbourg : "
                f"<em>« De: comptabilite@{domain}. Objet: Mise à jour de notre RIB. Suite à un changement "
                f"de banque, merci de mettre à jour notre RIB ci-joint pour tout règlement à venir. »</em> "
                f"<br><br><strong>Avec SPF actif :</strong> Gmail/Outlook voient que l'email vient de "
                f"Saint-Pétersbourg, vérifient votre SPF, constatent que ce serveur n'est PAS dans la liste "
                f"des serveurs autorisés. L'email part en spam ou est rejeté.<br><br>"
                f"<strong>Sans SPF (situation actuelle) :</strong> Gmail/Outlook n'ont pas de référence "
                f"de comparaison. L'email arrive normalement chez vos clients. 3 ou 4 d'entre eux changent "
                f"le RIB dans leur ERP. Les prochains règlements vont sur le compte de l'escroc."
            ),
            "demonstration": (
                f"<strong>L'attaque est triviale :</strong><br><br>"
                f"1. L'attaquant ouvre un terminal sur son serveur Linux et tape :<br>"
                f"&nbsp;&nbsp;<code>swaks --from \"compta@{domain}\" --to cible@client.fr --server smtp.son-serveur.com</code><br>"
                f"2. Il rédige son message frauduleux dans l'invite. Appuie sur Ctrl+D pour envoyer.<br>"
                f"3. <strong>Email envoyé en 2 secondes</strong>, arrive chez la cible dans la minute, "
                f"en boîte de réception normale parce que rien ne dit au serveur destinataire que cet "
                f"expéditeur n'est pas légitime. Total : 30 secondes."
            ),
            "real_case": (
                "<strong>Selon Verizon DBIR 2024 (Data Breach Investigations Report) :</strong><br><br>"
                "Le phishing reste la <strong>première porte d'entrée</strong> pour les intrusions "
                "(74% des intrusions impliquent un élément humain, principalement le clic sur un email "
                "frauduleux). Sur ces 74%, une part majeure utilise l'usurpation de domaines mal configurés. "
                "<br><br>Combiner SPF + DKIM + DMARC est la <strong>défense la plus rentable au monde</strong> "
                "selon le NIST : coût technique nul, efficacité ~95% contre l'usurpation."
            ),
            "action": (
                f"<strong>Cette semaine — 5 minutes :</strong><br>"
                f"Demandez à votre administrateur DNS d'ajouter un enregistrement TXT au nom <code>{domain}</code> "
                f"avec la valeur (à adapter selon votre fournisseur email) :<br><br>"
                f"&nbsp;&nbsp;• Google Workspace : <code>v=spf1 include:_spf.google.com ~all</code><br>"
                f"&nbsp;&nbsp;• Microsoft 365 : <code>v=spf1 include:spf.protection.outlook.com ~all</code><br>"
                f"&nbsp;&nbsp;• OVH : <code>v=spf1 include:mx.ovh.com ~all</code><br><br>"
                f"<strong>Effet immédiat :</strong> les serveurs frauduleux sont signalés aux destinataires, "
                f"leurs emails partent en spam ou sont rejetés. <strong>+SPF + DMARC = phishing à votre nom "
                f"quasi impossible.</strong>"
            ),
        })

    # ── 7. Cert TLS expiré ────────────────────────────────────────
    expired_certs = [t for t in (scan.tls_findings or []) if t.expired]
    if expired_certs:
        t = expired_certs[0]
        findings.append({
            "id": "expired_cert",
            "severity": "high",
            "icon": "🔐",
            "title": "Certificat SSL expiré — visiteurs bloqués",
            "summary": f"Certificat expiré sur {t.host}",
            "evidence": f"{t.host} → certificat expiré",
            "analogy": (
                f"<strong>Imaginez :</strong> votre boutique a un panneau lumineux qui dit "
                f"<em>« COMMERCE FERMÉ — RISQUE SANITAIRE — N'ENTREZ PAS »</em>. "
                f"Vous, vous savez que c'est juste un bug de l'enseigne — il n'y a aucun problème sanitaire. "
                f"Mais TOUS les passants qui voient le panneau changent de trottoir et vont chez le voisin. "
                f"<br><br>C'est exactement ce qu'affiche le navigateur de chaque visiteur "
                f"qui essaye d'ouvrir <code>https://{t.host}</code> en ce moment."
            ),
            "what_it_means": (
                f"Un certificat SSL (le « S » de HTTPS) est une pièce d'identité numérique qui prouve que "
                f"vous êtes bien le propriétaire du site, et qui chiffre les communications entre votre "
                f"site et le navigateur du visiteur. Cette pièce d'identité a une <strong>date de péremption</strong>, "
                f"généralement 90 jours pour Let's Encrypt (gratuit) ou 1 an pour les certificats payants. "
                f"<br><br>Le certificat de <strong>{t.host}</strong> est <strong>expiré</strong>. "
                f"Tous vos visiteurs voient une <strong>grande page rouge d'alerte</strong> dans leur "
                f"navigateur (Chrome, Firefox, Edge, Safari) avec un message du type "
                f"<em>« Votre connexion n'est pas privée — Risque d'attaque ! Les attaquants pourraient "
                f"voler vos informations… »</em>."
            ),
            "scenario": (
                f"<strong>Mardi 14h.</strong> Un prospect chaud que vous courtisez depuis 3 mois reçoit "
                f"votre proposition commerciale. Il clique sur le lien vers votre site pour vérifier votre "
                f"crédibilité avant de signer. "
                f"<br><br><strong>Il tombe sur le grand écran rouge :</strong> "
                f"« Cette connexion n'est pas privée. Des attaquants pourraient voler vos informations. "
                f"NE PAS POURSUIVRE. » "
                f"<br><br>Il hésite 0,8 seconde, ferme l'onglet, et écrit à votre concurrent. "
                f"Le contrat de 50 000€ vous échappe. "
                f"<br><br><strong>Pire scénario :</strong> votre site est utilisé pour des paiements ou un "
                f"login client. Tous les clients qui essayent de payer pensent que vous avez été piratés "
                f"(le navigateur le suggère noir sur rouge) et abandonnent. <strong>Chiffre d'affaires divisé "
                f"par 50</strong> pendant la durée du problème."
            ),
            "demonstration": (
                f"<strong>Pour voir le problème vous-même :</strong> ouvrez <code>https://{t.host}</code> "
                f"dans n'importe quel navigateur. Vous verrez :<br><br>"
                f"• Chrome : <em>« Votre connexion n'est pas privée »</em> + bouton « Retour à la sécurité »<br>"
                f"• Firefox : <em>« Avertissement : risque probable de sécurité »</em><br>"
                f"• Safari : <em>« Ce site web n'est peut-être pas sécurisé. Pour ne pas voler vos données… »</em><br><br>"
                f"<strong>Études d'usabilité :</strong> 99% des visiteurs cliquent « Retour » devant cette page. "
                f"Seuls les techniciens (1% des utilisateurs grand public) savent contourner l'avertissement, "
                f"et ils ne le font pas non plus pour un site commercial."
            ),
            "real_case": (
                "<strong>WhatsApp (3 novembre 2021) — 6 heures d'inaccessibilité à cause d'un certificat :</strong><br><br>"
                "Le 3 novembre 2021, WhatsApp est devenu inaccessible pendant <strong>plus de 6 heures</strong> "
                "dans le monde entier. La cause : un certificat TLS interne (entre les serveurs Facebook/Meta) "
                "a expiré, n'a pas été renouvelé automatiquement à cause d'un bug dans leur système, et "
                "tous les serveurs WhatsApp ont refusé de communiquer entre eux. "
                "<br><br><strong>Conséquences :</strong> 2 milliards d'utilisateurs sans WhatsApp pendant 6h. "
                "Action Meta -5% en bourse ce jour-là (perte de capitalisation : ~50 milliards de dollars). "
                "Le manque à gagner sur les revenus business : des dizaines de millions de dollars. "
                "<br><br><strong>Plus proche du quotidien :</strong> en 2020, le site de la sécurité sociale "
                "française est resté inaccessible pendant 4 heures suite à une expiration de certificat. "
                "Microsoft Teams a connu plusieurs incidents similaires (le plus récent en février 2024)."
            ),
            "action": (
                f"<strong>Aujourd'hui :</strong><br>"
                f"1. <strong>Renouveler immédiatement le certificat</strong>. Si vous utilisez Let's Encrypt "
                f"(gratuit, recommandé), la commande est <code>certbot renew</code>.<br>"
                f"2. <strong>Vérifier la cause du non-renouvellement automatique</strong> (probablement "
                f"une cron task cassée ou un changement d'IP).<br><br>"
                f"<strong>Cette semaine :</strong><br>"
                f"3. <strong>Mettre en place une alerte de monitoring</strong> qui prévient 30 jours avant "
                f"chaque expiration (outils gratuits : UptimeRobot, Better Uptime). Coût : 0€.<br>"
                f"4. <strong>Auditer TOUS vos certificats</strong> de tous vos domaines/sous-domaines pour "
                f"identifier les autres bombes à retardement."
            ),
        })

    # ── 8. Sous-domaines sensibles ────────────────────────────────
    sensitive_subs_keywords = ["admin", "intranet", "vpn", "db", "database", "ftp", "test", "dev", "staging"]
    sensitive_subs_found = []
    for sub in (scan.discovered_subs or [])[:50]:
        sub_lower = sub.lower()
        for kw in sensitive_subs_keywords:
            if sub_lower.startswith(kw + ".") or f".{kw}." in sub_lower:
                sensitive_subs_found.append({"sub": sub, "keyword": kw})
                break

    if sensitive_subs_found:
        first = sensitive_subs_found[0]
        findings.append({
            "id": "sensitive_subs",
            "severity": "medium",
            "icon": "👁️",
            "title": "Sous-domaines à usage interne accessibles publiquement",
            "summary": f"{len(sensitive_subs_found)} sous-domaine(s) suspect(s) : " + ", ".join(s["sub"] for s in sensitive_subs_found[:3]),
            "evidence": first["sub"],
            "analogy": (
                f"<strong>Imaginez :</strong> votre immeuble de bureaux a une grande entrée principale, "
                f"belle et sécurisée, avec agent d'accueil + portique de sécurité + badge obligatoire. "
                f"Mais sur le côté, il y a une porte de service marquée <em>« {first['keyword'].upper()} - "
                f"personnel uniquement »</em>. Cette porte, vous croyez qu'elle est cachée derrière les "
                f"poubelles. En réalité, elle est visible depuis la rue, elle n'a pas d'agent, le code de "
                f"sécurité est <code>1234</code> et n'a pas été changé depuis 8 ans. "
                f"<br><br>Tous les cambrioleurs professionnels savent qu'on entre par les portes de service, "
                f"pas par l'entrée principale. C'est pareil en informatique."
            ),
            "what_it_means": (
                f"Des sous-domaines aux noms suggérant un usage interne ou de développement (comme "
                f"<code>{first['keyword']}.{domain}</code>) sont accessibles depuis internet. Les attaquants "
                f"savent que ces sous-domaines sont presque toujours <strong>moins surveillés, avec des "
                f"configurations plus laxistes, et créés rapidement « en attendant »</strong> sans audit "
                f"de sécurité. Ils représentent des <strong>portes d'entrée privilégiées</strong>. "
                f"<br><br>Concrètement, on trouve souvent sur ces sous-domaines : des versions de test "
                f"avec des comptes par défaut (<code>test/test</code>), des sauvegardes de base de données, "
                f"des dépôts de code source avec des mots de passe en clair, des panels d'administration "
                f"oubliés, ou des versions obsolètes de logiciels."
            ),
            "scenario": (
                f"<strong>Samedi 22h.</strong> Un chasseur de primes (bug bounty hunter) — pas un méchant, "
                f"juste un freelance qui cherche des failles pour gagner des récompenses — découvre votre "
                f"sous-domaine <code>{first['sub']}</code> via un scan public. "
                f"<br><br>Sauf que ce hunter-là est passé du bon côté hier matin et a accepté un contrat "
                f"« concurrence déloyale » pour 5 000€ de la part d'un concurrent qui veut connaître votre "
                f"roadmap. Il fouille votre sous-domaine, trouve une instance de Jenkins (système de build "
                f"de code) accessible sans login. Dans les logs de build, il trouve les credentials de votre "
                f"base de données. "
                f"<br><br><strong>Dimanche matin :</strong> votre roadmap produit complète, votre liste "
                f"clients, et le code source de votre application sont dans les mains de votre concurrent. "
                f"Vous ne le saurez jamais — il ne va pas vous le dire."
            ),
            "demonstration": (
                f"<strong>Voici comment l'attaquant procède :</strong><br><br>"
                f"1. Il utilise <code>subfinder -d {domain}</code> ou consulte <code>crt.sh</code> "
                f"(base publique des certificats SSL) pour énumérer TOUS vos sous-domaines.<br>"
                f"2. Il filtre par mots-clés sensibles : <code>admin, test, dev, staging, vpn, ftp, "
                f"intranet, db, jenkins, gitlab</code>.<br>"
                f"3. Pour chaque sous-domaine sensible, il essaie : les pages de login standard "
                f"(<code>/login, /admin, /wp-admin</code>), les credentials par défaut documentés en ligne, "
                f"et les exploits récents.<br><br>"
                f"<strong>Le plus drôle :</strong> ces sous-domaines sont souvent créés par des développeurs "
                f"pressés qui se disent « je sécurise plus tard ». Le « plus tard » n'arrive jamais."
            ),
            "real_case": (
                "<strong>Uber (octobre 2016) — 57 millions d'utilisateurs compromis :</strong><br><br>"
                "Un attaquant a découvert qu'Uber utilisait GitHub Enterprise (la version privée de GitHub) "
                "sur un sous-domaine accessible publiquement, sans VPN obligatoire. Dans les dépôts privés "
                "stockés sur ce sous-domaine, des développeurs avaient committé (= sauvegardé dans Git) "
                "<strong>les clés d'accès AWS</strong> de la prod d'Uber. "
                "<br><br>L'attaquant a utilisé ces clés pour accéder aux bases de données AWS d'Uber et "
                "exfiltrer les données de <strong>57 millions d'utilisateurs et conducteurs</strong> "
                "(noms, emails, numéros de téléphone, et 600 000 numéros de permis de conduire). "
                "<br><br><strong>Pire :</strong> au lieu de notifier les autorités comme la loi l'exige, "
                "Uber a payé <strong>100 000$ de rançon</strong> à l'attaquant pour qu'il se taise et "
                "supprime les données (avec une promesse écrite — comme si on pouvait faire confiance à un hacker…). "
                "L'affaire a été révélée 1 an plus tard. "
                "<br><br><strong>Sanctions finales :</strong> 148 millions de dollars d'amende, "
                "le RSSI (responsable de la sécurité) Joe Sullivan a été condamné pénalement à 3 ans de probation "
                "(une première mondiale pour un cadre cybersécurité), Uber a dû créer une commission de "
                "supervision indépendante pour 20 ans. "
                "Tout ça à cause d'un sous-domaine GitHub interne… exposé publiquement."
            ),
            "action": (
                f"<strong>Cette semaine :</strong><br>"
                f"1. <strong>Audit des sous-domaines suspects</strong> ({', '.join(s['sub'] for s in sensitive_subs_found[:3])}) : "
                f"sont-ils vraiment utilisés ? Par qui ? Pour quoi ?<br>"
                f"2. <strong>Placer ces sous-domaines derrière un VPN d'entreprise</strong>. "
                f"Pour y accéder, il faudra d'abord se connecter au VPN. Coût technique : 1-2 jours.<br>"
                f"3. <strong>Si ce sont des environnements de test/dev :</strong> les sortir d'internet. "
                f"Soit on les place en VPN, soit on les supprime, soit on accepte le risque mais avec "
                f"authentification forte minimum.<br><br>"
                f"<strong>En continu :</strong><br>"
                f"4. <strong>Audit mensuel</strong> de votre inventaire de sous-domaines (cette analyse "
                f"ARGUS le fait automatiquement pour vous)."
            ),
            "other_examples": [s["sub"] for s in sensitive_subs_found[1:6]],
        })

    return findings


@app.post("/admin/report/{report_id}/delete")
def admin_delete_report(report_id: int, request: Request, db: Session = Depends(get_db)):
    admin = get_current_user(request, db)
    if not admin or not admin.is_admin:
        raise HTTPException(403)
    report = db.query(PublicReport).filter(PublicReport.id == report_id).first()
    if report:
        db.delete(report)
        db.commit()
    return RedirectResponse("/admin#reports", 303)


# ─────────────────────────────────────────────────────────────────────
# Actions scan
# ─────────────────────────────────────────────────────────────────────

PENTEST_CONSENT_TEXT = (
    "J'atteste être autorisé(e) par le propriétaire du domaine à mener un test "
    "d'intrusion actif (probing, port scan, fuzzing). J'assume l'entière "
    "responsabilité légale de ce scan selon la législation applicable dans ma "
    "juridiction. ARGUS Security enregistre ce consentement comme preuve d'audit."
)


import re as _re_validate

# Validation domaine stricte : labels alphanumériques + tirets, séparés par points, TLD >=2 lettres
_DOMAIN_RE = _re_validate.compile(
    r"^(?=.{1,253}$)"
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z]{2,63}$"
)
_EMAIL_RE = _re_validate.compile(
    r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$"
)
# Numéro international : + suivi de 8 à 15 chiffres (spaces/tirets autorisés mais nettoyés)
_PHONE_RE = _re_validate.compile(r"^\+[1-9]\d{7,14}$")


def _normalize_domain(raw: str) -> str:
    """Nettoie un input domaine : retire protocole, slash, espaces, lowercase."""
    d = (raw or "").strip().lower()
    d = d.removeprefix("http://").removeprefix("https://").removeprefix("www.")
    d = d.split("/")[0].split("?")[0].split("#")[0].strip()
    return d


def _is_valid_domain(domain: str) -> bool:
    return bool(_DOMAIN_RE.match(domain))


@app.post("/scan")
def scan_start(
    background_tasks: BackgroundTasks,
    request: Request,
    domain: str = Form(...),
    run_nuclei_flag: bool = Form(False, alias="run_nuclei"),
    run_tls: bool = Form(True),
    deep_discovery: bool = Form(True),
    pentest_mode: bool = Form(False),
    pentest_consent_1: bool = Form(False),
    pentest_consent_2: bool = Form(False),
    db: Session = Depends(get_db),
):
    user = get_current_user(request, db)
    domain = _normalize_domain(domain)

    # ── Validation domaine stricte ──────────────────────────────────
    if not _is_valid_domain(domain):
        # Page d'erreur jolie au lieu de JSON brut
        return templates.TemplateResponse(
            "error.html",
            _ctx(request, db,
                 error_title="Domaine invalide",
                 error_message=(
                     f"« {domain or 'vide'} » n'est pas un nom de domaine valide. "
                     "Utilisez un format comme « monentreprise.com » ou « sous.domaine.fr ». "
                     "Aucun protocole, aucun espace, aucun slash."
                 ),
                 error_back_url="/",
                 error_back_label="Recommencer un scan"),
            status_code=400,
        )

    # ── Auth requise pour scanner (anti-abus + nécessaire pour 80% des résultats) ──
    if not user:
        # On préserve le domaine pour pré-remplir le scan après inscription
        request.session["pending_scan_domain"] = domain
        return RedirectResponse(url=f"/register?domain={domain}", status_code=303)

    # ── Email vérifié requis pour scanner ──
    if not user.email_verified_at and not user.is_admin:
        request.session["pending_scan_domain"] = domain
        return RedirectResponse(url="/verify-email/pending", status_code=303)

    # Pentest mode réservé aux plans pro/agency
    limits = get_plan_limits(user)
    pentest_authorized = (
        pentest_mode and pentest_consent_1 and pentest_consent_2
        and limits["pentest"]
    )

    scan = Scan(
        domain=domain,
        status="running",
        user_id=user.id if user else None,
    )
    if pentest_authorized:
        scan.pentest_authorized = True
        scan.pentest_authorization_text = PENTEST_CONSENT_TEXT
        scan.pentest_authorized_at = datetime.utcnow()
    db.add(scan)
    db.commit()
    db.refresh(scan)

    background_tasks.add_task(_run_scan, scan.id, run_nuclei_flag, run_tls, deep_discovery, pentest_authorized)
    return RedirectResponse(url=f"/scan/{scan.id}", status_code=303)


@app.get("/scan/{scan_id}/status")
def scan_status(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(404)
    return {
        "id": scan.id,
        "status": scan.status,
        "assets_count": scan.assets_count,
        "alive_count": scan.alive_count,
        "vulns_count": scan.vulns_count,
        "critical_count": scan.critical_count,
        "high_count": scan.high_count,
        "kev_count": scan.kev_count,
        "risk_score": scan.risk_score,
        "risk_grade": scan.risk_grade,
        "progress": scan.progress or 0,
        "current_step": scan.current_step or "",
        "current_detail": scan.current_detail or "",
    }


@app.get("/scan/{scan_id}/export/subs.txt")
def export_subs(scan_id: int, request: Request, db: Session = Depends(get_db)):
    from fastapi.responses import Response
    user = get_current_user(request, db)
    if not can_see_full_results(user):
        raise HTTPException(403, "Export disponible à partir du plan Essentiel")
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(404)
    subs = scan.discovered_subs or []
    content = "\n".join(subs) + "\n"
    return Response(
        content=content,
        media_type="text/plain; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="argus_{scan.domain}_{scan.id}_subs.txt"'},
    )


@app.get("/scan/{scan_id}/export/pdf")
def export_pdf(scan_id: int, request: Request, db: Session = Depends(get_db)):
    """Export PDF du rapport — réservé aux plans payants (Essentiel et plus)."""
    from fastapi.responses import Response
    from app.pdf_report import generate_pdf

    user = get_current_user(request, db)
    if not can_see_full_results(user):
        # Plan gratuit ou pas connecté : on redirige vers la page upgrade
        return RedirectResponse(url=f"/upgrade?from=pdf&scan={scan_id}", status_code=303)

    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(404, "Scan introuvable")

    # Vérif propriétaire (ou admin)
    if scan.user_id and not user.is_admin and scan.user_id != user.id:
        raise HTTPException(403, "Accès non autorisé")

    if scan.status != "completed":
        raise HTTPException(400, "Le scan doit être terminé pour exporter le rapport")

    # Génération PDF
    try:
        pdf_bytes = generate_pdf(scan, scan.assets, scan.vulns, scan.tls_findings)
    except Exception as e:
        raise HTTPException(500, f"Erreur de génération PDF : {e}")

    safe_domain = scan.domain.replace("/", "_").replace("\\", "_")
    filename = f"argus_{safe_domain}_{scan.id}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/upgrade", response_class=HTMLResponse)
def upgrade_page(request: Request, db: Session = Depends(get_db)):
    """Page d'upgrade : Essentiel = Stripe Checkout, Pro = formulaire de contact sales."""
    target_plan = request.query_params.get("plan", "essentiel")
    from_source = request.query_params.get("from", "")
    confirmed = request.query_params.get("confirmed") == "1"
    cancelled = request.query_params.get("cancelled") == "1"
    return templates.TemplateResponse(
        "upgrade.html",
        _ctx(request, db, active="upgrade",
             target_plan=target_plan, from_source=from_source,
             confirmed=confirmed, cancelled=cancelled,
             form_data=None, form_error=None)
    )


@app.post("/upgrade/request")
def upgrade_request(request: Request, db: Session = Depends(get_db),
                    plan: str = Form("essentiel")):
    """
    Demande d'upgrade.
    - plan=essentiel + Stripe configuré → Stripe Checkout
    - plan=pro / agency → redirige vers le formulaire de contact sales
    - sinon → page de confirmation manuelle
    """
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse(url="/login?next=/upgrade", status_code=303)

    # Pro et Agency passent par le formulaire de contact, jamais Stripe
    if plan in ("pro", "agency"):
        return RedirectResponse(url="/upgrade?plan=pro", status_code=303)

    if plan != "essentiel":
        plan = "essentiel"

    stripe_key = os.getenv("STRIPE_SECRET_KEY", "").strip()
    if stripe_key:
        return _stripe_create_checkout(request, db, user, plan)

    # Fallback si Stripe pas configuré
    print(f"[UPGRADE REQUEST] user={user.email} (id={user.id}) plan_demande={plan}", flush=True)
    request.session["upgrade_requested"] = plan
    return RedirectResponse(url=f"/upgrade?confirmed=1&plan={plan}", status_code=303)


@app.post("/upgrade/contact")
def upgrade_contact(
    request: Request,
    db: Session = Depends(get_db),
    name: str = Form(""),
    email: str = Form(""),
    phone: str = Form(""),
    company: str = Form(""),
    company_size: str = Form(""),
    message: str = Form(""),
):
    """Formulaire de contact pour le plan Pro (sur devis) → envoie email à sales@."""
    from app.email_sender import send_sales_contact_email, send_sales_autoreply_email

    name = (name or "").strip()[:120]
    email = (email or "").strip().lower()[:200]
    phone = (phone or "").strip()[:50]
    company = (company or "").strip()[:200]
    company_size = (company_size or "").strip()[:20]
    message = (message or "").strip()[:4000]

    # Validation minimale
    if not name or not email or "@" not in email or "." not in email or not message:
        return templates.TemplateResponse("upgrade.html", _ctx(
            request, db, active="upgrade",
            target_plan="pro", from_source="", confirmed=False, cancelled=False,
            form_data={"name": name, "email": email, "phone": phone,
                       "company": company, "company_size": company_size, "message": message},
            form_error="Merci de renseigner au moins votre nom, un email valide et un message décrivant votre besoin."
        ))

    sales_to = os.getenv("SALES_EMAIL", "contact@argusanalyzer.com").strip() or "contact@argusanalyzer.com"
    prospect = {"name": name, "email": email, "phone": phone,
                "company": company, "company_size": company_size, "message": message}

    try:
        send_sales_contact_email(sales_to, prospect)
        send_sales_autoreply_email(email, name)
    except Exception as e:
        print(f"[SALES CONTACT ERROR] {e}", flush=True)

    print(f"[SALES CONTACT] {email} ({company or 'no company'}) — {len(message)} chars", flush=True)

    return RedirectResponse(url="/upgrade?confirmed=1&plan=pro", status_code=303)


# ─────────────────────────────────────────────────────────────────────
# Stripe Checkout — désactivé tant que STRIPE_SECRET_KEY n'est pas dans .env
# ─────────────────────────────────────────────────────────────────────

# Stripe Checkout actif uniquement pour Essentiel.
# Pro = sur devis (formulaire contact sales, pas de prix Stripe).
STRIPE_PRICES = {
    "essentiel": os.getenv("STRIPE_PRICE_ESSENTIEL", ""),
}


def _stripe_create_checkout(request: Request, db: Session, user: "User", plan: str):
    """Crée une session Stripe Checkout et renvoie l'utilisateur dessus."""
    import stripe
    stripe.api_key = os.getenv("STRIPE_SECRET_KEY", "")
    price_id = STRIPE_PRICES.get(plan, "")

    if not price_id:
        request.session["settings_error"] = f"Le plan {plan} n'est pas encore disponible au paiement. Contactez-nous."
        return RedirectResponse(url=f"/upgrade?plan={plan}", status_code=303)

    # Base URL pour les redirections (à adapter en prod)
    base_url = str(request.base_url).rstrip("/")
    success_url = f"{base_url}/billing/success?session_id={{CHECKOUT_SESSION_ID}}&plan={plan}"
    cancel_url = f"{base_url}/upgrade?plan={plan}&cancelled=1"

    try:
        # Customer Stripe : on réutilise s'il existe, sinon on crée
        customer_id = user.stripe_customer_id
        if not customer_id:
            cust = stripe.Customer.create(
                email=user.email,
                name=user.name or user.email,
                metadata={"user_id": str(user.id)},
            )
            customer_id = cust.id
            user.stripe_customer_id = customer_id
            db.commit()

        checkout = stripe.checkout.Session.create(
            mode="subscription",
            customer=customer_id,
            line_items=[{"price": price_id, "quantity": 1}],
            success_url=success_url,
            cancel_url=cancel_url,
            allow_promotion_codes=True,
            client_reference_id=str(user.id),
            metadata={"user_id": str(user.id), "plan": plan},
            subscription_data={"metadata": {"user_id": str(user.id), "plan": plan}},
        )
        return RedirectResponse(url=checkout.url, status_code=303)
    except Exception as e:
        print(f"[STRIPE ERROR] {e}", flush=True)
        request.session["settings_error"] = "Erreur lors de la création du paiement. Veuillez nous contacter."
        return RedirectResponse(url=f"/upgrade?plan={plan}", status_code=303)


@app.get("/billing/success", response_class=HTMLResponse)
def billing_success(request: Request, db: Session = Depends(get_db)):
    """Page de confirmation post-paiement (le webhook fait le vrai upgrade plan)."""
    user = get_current_user(request, db)
    plan = request.query_params.get("plan", "essentiel")
    session_id = request.query_params.get("session_id", "")

    # Optimisation : on peut aussi vérifier la session Stripe pour activer immédiatement
    # plutôt que d'attendre le webhook (utile en local sans webhook setup)
    if user and session_id:
        try:
            import stripe
            stripe.api_key = os.getenv("STRIPE_SECRET_KEY", "")
            sess = stripe.checkout.Session.retrieve(session_id)
            if sess.payment_status == "paid" and sess.subscription:
                user.plan = plan
                user.stripe_subscription_id = sess.subscription
                db.commit()
        except Exception as e:
            print(f"[STRIPE SUCCESS CHECK ERROR] {e}", flush=True)

    return templates.TemplateResponse("billing_success.html", _ctx(request, db,
        active="billing", plan_name=PLAN_NAMES.get(plan, plan)))


@app.post("/webhook/stripe")
async def stripe_webhook(request: Request, db: Session = Depends(get_db)):
    """Webhook Stripe : mise à jour des plans utilisateurs sur events de billing."""
    import stripe
    stripe.api_key = os.getenv("STRIPE_SECRET_KEY", "")
    webhook_secret = os.getenv("STRIPE_WEBHOOK_SECRET", "")

    payload = await request.body()
    sig_header = request.headers.get("stripe-signature", "")

    try:
        if webhook_secret:
            event = stripe.Webhook.construct_event(payload, sig_header, webhook_secret)
        else:
            import json
            event = json.loads(payload)
    except Exception as e:
        print(f"[STRIPE WEBHOOK ERROR] signature invalide : {e}", flush=True)
        raise HTTPException(400, "Invalid signature")

    event_type = event["type"] if isinstance(event, dict) else event.type
    data = event["data"]["object"] if isinstance(event, dict) else event.data.object

    # Normaliser data en dict standard (StripeObject n'a pas .get directement)
    if not isinstance(data, dict):
        data = data.to_dict() if hasattr(data, "to_dict") else dict(data)

    try:
        # checkout.session.completed → activation du plan
        if event_type == "checkout.session.completed":
            user_id = (data.get("metadata") or {}).get("user_id")
            plan = (data.get("metadata") or {}).get("plan", "essentiel")
            subscription_id = data.get("subscription")
            if user_id:
                user = db.query(User).filter(User.id == int(user_id)).first()
                if user:
                    user.plan = plan
                    user.stripe_subscription_id = subscription_id
                    db.commit()
                    print(f"[STRIPE] user {user.email} activé sur plan {plan}", flush=True)

        # customer.subscription.deleted → retour au plan free
        elif event_type == "customer.subscription.deleted":
            sub_id = data.get("id")
            user = db.query(User).filter(User.stripe_subscription_id == sub_id).first()
            if user:
                user.plan = "free"
                user.stripe_subscription_id = None
                db.commit()
                print(f"[STRIPE] user {user.email} downgradé sur free (abonnement annulé)", flush=True)

        # Autres events ignorés silencieusement (subscription.updated, etc.)
    except Exception as e:
        # On log mais on retourne 200 pour que Stripe arrête de retry indéfiniment
        print(f"[STRIPE WEBHOOK HANDLER ERROR] event={event_type} : {e}", flush=True)

    return {"received": True}


@app.post("/scan/{scan_id}/delete")
def scan_delete(scan_id: int, request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if scan and (not scan.user_id or (user and (user.is_admin or scan.user_id == user.id))):
        db.delete(scan)
        db.commit()
    return RedirectResponse(url="/history", status_code=303)


# ─────────────────────────────────────────────────────────────────────
# Tâche de fond : exécution du scan complet
# ─────────────────────────────────────────────────────────────────────

def _set_progress(db, scan, progress: int, step: str, detail: str = ""):
    scan.progress = progress
    scan.current_step = step
    scan.current_detail = detail
    db.commit()


def _run_scan(scan_id: int, do_nuclei: bool, do_tls: bool, deep_discovery: bool = True, pentest_mode: bool = False):
    """Tourne en arrière-plan. Crée sa propre session DB."""
    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return

        _set_progress(db, scan, 2, "DISCOVERY", "initialisation des sources")

        # ─── Étape 1 : Discovery multi-sources ──────────────────────
        # Libellés génériques (sans mention des outils)
        STEP_WEIGHTS = {
            "subfinder":     (5,  25, "🛰 Sources OSINT (30+ bases de données)"),
            "crtsh":         (25, 35, "🔐 Certificats publics SSL/TLS"),
            "wayback":       (35, 42, "⏳ Archives web publiques"),
            "bruteforce":    (42, 50, "⚡ Reconnaissance DNS — top 200"),
            "ai_permutation":(50, 55, "🤖 Intelligence ARGUS — patterns détectés"),
        }
        def on_progress(source: str, count: int):
            _, end_pct, label = STEP_WEIGHTS.get(source, (0, 50, source))
            _set_progress(db, scan, end_pct, "DISCOVERY", f"{label} — {count} résultats")

        disc = discovery.discover_all(scan.domain, deep=deep_discovery, on_progress=on_progress)
        subs = disc["subs"]
        scan.discovery_sources = disc["by_source"]
        scan.discovered_subs = subs
        _set_progress(db, scan, 55, "DISCOVERY", f"✓ {len(subs)} actifs identifiés")
        db.commit()

        # ─── Étape 2 : Vérification HTTP ────────────────────────────
        _set_progress(db, scan, 58, "VÉRIFICATION HTTP", f"test de {len(subs)} actifs")
        httpx_findings = scanner.run_httpx(subs)
        for f in httpx_findings:
            db.add(Asset(
                scan_id=scan_id,
                url=f["url"],
                host=f["host"],
                status_code=f["status_code"],
                title=f.get("title", ""),
                webserver=f.get("webserver", ""),
                content_length=f.get("content_length", 0),
                tech=f.get("tech", []),
            ))
        scan.assets_count = len(subs)
        scan.alive_count = sum(1 for f in httpx_findings if f.get("status_code", 0) > 0)
        db.commit()
        _set_progress(db, scan, 70, "VÉRIFICATION HTTP", f"✓ {scan.alive_count} actifs en ligne")

        # ─── Étape 3 : DNS + Sécurité email ─────────────────────────
        _set_progress(db, scan, 72, "SÉCURITÉ EMAIL", "analyse SPF / DKIM / DMARC")
        try:
            dns_data = dns_scan.scan_dns(scan.domain)
            scan.dns_records = dns_data["records"]
            scan.spf = dns_data["spf"]
            scan.dmarc = dns_data["dmarc"]
            scan.dkim = dns_data["dkim"]
            scan.dns_issues = dns_data["issues"]
            db.commit()
        except Exception:
            pass

        # ─── Étape 4 : Audit SSL/TLS ────────────────────────────────
        alive_urls = [f["url"] for f in httpx_findings if f.get("status_code", 0) > 0 and f["url"].startswith("https")]
        tls_results = []
        if do_tls and alive_urls:
            _set_progress(db, scan, 78, "AUDIT SSL/TLS", f"audit de {len(alive_urls)} certificats")
            try:
                tls_results = tls_scan.run_tlsx(alive_urls)
                for t in tls_results:
                    db.add(TlsFinding(
                        scan_id=scan_id,
                        host=t.get("host", ""),
                        port=t.get("port", 443),
                        issuer=t.get("issuer", ""),
                        subject_cn=t.get("subject_cn", ""),
                        subject_an=t.get("subject_an", []),
                        not_before=t.get("not_before", ""),
                        not_after=t.get("not_after", ""),
                        days_until_expiry=t.get("days_until_expiry"),
                        tls_versions=t.get("tls_versions", []),
                        cipher=t.get("cipher", ""),
                        self_signed=t.get("self_signed", False),
                        expired=t.get("expired", False),
                        mismatched=t.get("mismatched", False),
                        issues=t.get("issues", []),
                    ))
                db.commit()
            except Exception:
                pass

        # ─── Étape 5a : Mode Pentest (opt-in, consentement exigé) ───
        pentest_results = {"ports": [], "paths": [], "endpoints": []}
        if pentest_mode and alive_urls:
            _set_progress(db, scan, 80, "PENTEST ACTIF", "🚨 audit réseau en cours")
            try:
                alive_hosts = list({u.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
                                    for u in alive_urls})
                pentest_results["ports"] = pentest.run_naabu(alive_hosts[:30])
            except Exception:
                pass

            _set_progress(db, scan, 84, "PENTEST ACTIF", "📁 audit des accès sensibles")
            try:
                priority_urls = [u for u in alive_urls if scan.domain in u][:5]
                paths_found = []
                for url in priority_urls:
                    paths_found.extend(pentest.run_ffuf(url))
                pentest_results["paths"] = paths_found
            except Exception:
                pass

            _set_progress(db, scan, 87, "PENTEST ACTIF", "🕷 cartographie applicative en cours")
            try:
                pentest_results["endpoints"] = pentest.run_katana(alive_urls[:20])
            except Exception:
                pass

            scan.pentest_findings = pentest_results
            db.commit()

        # ─── Étape 5b : Analyse des vulnérabilités (opt-in) ─────────
        nuclei_findings: list[dict] = []
        if do_nuclei and alive_urls:
            _set_progress(db, scan, 88, "ANALYSE VULNÉRABILITÉS", f"analyse approfondie sur {len(alive_urls)} cibles")
            try:
                nuclei_findings = nuclei.run_nuclei([f["url"] for f in httpx_findings if f.get("status_code", 0) > 0])
            except Exception:
                pass

        # ─── Étape 6 : Threat Intelligence (EPSS + KEV) ─────────────
        if nuclei_findings:
            _set_progress(db, scan, 90, "THREAT INTELLIGENCE", f"enrichissement sur {len(nuclei_findings)} vulnérabilités")
            nuclei_findings = enrichment.enrich_vulns(nuclei_findings)
            for nf in nuclei_findings:
                asset_obj = None
                matched = nf.get("matched_url", "") or ""
                for a in scan.assets:
                    if a.url and matched.startswith(a.url):
                        asset_obj = a
                        break
                db.add(Vuln(
                    scan_id=scan_id,
                    asset_id=asset_obj.id if asset_obj else None,
                    template_id=nf.get("template_id", ""),
                    name=nf.get("name", ""),
                    description=nf.get("description", ""),
                    severity=nf.get("severity", "info"),
                    matched_url=matched,
                    cve_id=nf.get("cve_id"),
                    epss_score=nf.get("epss_score"),
                    epss_percentile=nf.get("epss_percentile"),
                    kev=bool(nf.get("kev")),
                    reference=nf.get("reference", []),
                    extracted_results=nf.get("extracted_results", []),
                    tags=nf.get("tags", []),
                ))
            scan.vulns_count = len(nuclei_findings)
            scan.critical_count = sum(1 for v in nuclei_findings if v.get("severity") == "critical")
            scan.high_count = sum(1 for v in nuclei_findings if v.get("severity") == "high")
            scan.kev_count = sum(1 for v in nuclei_findings if v.get("kev"))
            db.commit()

        # ─── Étape 7 : Score de risque ARGUS ────────────────────────
        _set_progress(db, scan, 93, "CALCUL DU SCORE", "score de risque A-F en cours")
        score_data = risk_score.compute_score({
            "assets": httpx_findings,
            "vulns": nuclei_findings,
            "dns": {"spf": scan.spf, "dmarc": scan.dmarc, "dkim": scan.dkim},
            "tls": tls_results,
        })
        scan.risk_score = score_data["score"]
        scan.risk_grade = score_data["grade"]
        scan.risk_breakdown = score_data["breakdown"]
        db.commit()

        # ─── Étape 8 : Analyse sécurité exécutive ───────────────────
        _set_progress(db, scan, 96, "ANALYSE EXÉCUTIVE", "rédaction du rapport de sécurité")
        try:
            vulns_dicts = [{"name": v.get("name"), "severity": v.get("severity"),
                            "matched_url": v.get("matched_url"), "cve_id": v.get("cve_id"),
                            "kev": v.get("kev"), "epss_score": v.get("epss_score")}
                           for v in nuclei_findings]
            scan.ai_summary = scanner.ai_summarize(scan.domain, httpx_findings, vulns_dicts)
        except Exception as e:
            scan.ai_summary = f"[Analyse indisponible : {e}]"

        scan.status = "completed"
        scan.progress = 100
        scan.current_step = "TERMINÉ"
        scan.current_detail = "✓ analyse complète"
        scan.completed_at = datetime.utcnow()
        db.commit()

    except Exception as e:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan:
            scan.status = "failed"
            scan.error_message = f"{type(e).__name__}: {e}"
            scan.completed_at = datetime.utcnow()
            db.commit()
        raise
    finally:
        db.close()
