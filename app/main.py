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
                        PasswordResetToken, EmailVerificationToken,
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
        plan_limits=get_plan_limits(user),
    ))


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
    """Page intermédiaire d'upgrade — Stripe arrive bientôt, en attendant on collecte la demande."""
    target_plan = request.query_params.get("plan", "essentiel")
    from_source = request.query_params.get("from", "")
    confirmed = request.query_params.get("confirmed") == "1"
    return templates.TemplateResponse(
        "upgrade.html",
        _ctx(request, db, active="upgrade",
             target_plan=target_plan, from_source=from_source, confirmed=confirmed)
    )


@app.post("/upgrade/request")
def upgrade_request(request: Request, db: Session = Depends(get_db),
                    plan: str = Form("essentiel")):
    """
    Point d'entrée d'upgrade.
    - Si Stripe est configuré (STRIPE_SECRET_KEY présent) → redirige vers Stripe Checkout
    - Sinon → enregistre la demande (mode demande de contact)
    """
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse(url="/login?next=/upgrade", status_code=303)

    if plan not in ("essentiel", "pro", "agency"):
        plan = "essentiel"

    # Stripe activé ?
    stripe_key = os.getenv("STRIPE_SECRET_KEY", "").strip()
    if stripe_key:
        # On crée une session de checkout
        return _stripe_create_checkout(request, db, user, plan)

    # Mode fallback : log + page de confirmation manuelle
    print(f"[UPGRADE REQUEST] user={user.email} (id={user.id}) plan_demande={plan}", flush=True)
    request.session["upgrade_requested"] = plan
    return RedirectResponse(url=f"/upgrade?confirmed=1&plan={plan}", status_code=303)


# ─────────────────────────────────────────────────────────────────────
# Stripe Checkout — désactivé tant que STRIPE_SECRET_KEY n'est pas dans .env
# ─────────────────────────────────────────────────────────────────────

# Prix Stripe par plan (à créer dans le dashboard Stripe puis mettre les IDs ici ou en env)
STRIPE_PRICES = {
    "essentiel": os.getenv("STRIPE_PRICE_ESSENTIEL", ""),
    "pro":       os.getenv("STRIPE_PRICE_PRO", ""),
    "agency":    os.getenv("STRIPE_PRICE_AGENCY", ""),
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
