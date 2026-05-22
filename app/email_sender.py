"""
email_sender.py — Envoi d'emails transactionnels ARGUS.

Fonctionne en 2 modes :
  1. SMTP configuré (SMTP_HOST, SMTP_USER, SMTP_PASSWORD dans .env)
     → envoie vraiment l'email via SMTP (TLS)
  2. Pas de SMTP configuré (dev local)
     → écrit l'email dans logs/emails/<timestamp>.html (pour preview)
     → log un résumé dans la console

Pas de mention "Claude/Anthropic/IA" dans les emails.
Pas de mention de localisation.
"""

import os
import smtplib
import ssl
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path


# ─── Config SMTP (lue à chaque envoi pour permettre la mise à jour) ─

def _smtp_config() -> dict:
    return {
        "host": os.getenv("SMTP_HOST", "").strip(),
        "port": int(os.getenv("SMTP_PORT", "587") or 587),
        "user": os.getenv("SMTP_USER", "").strip(),
        "password": os.getenv("SMTP_PASSWORD", "").strip(),
        "from_email": os.getenv("SMTP_FROM_EMAIL", "no-reply@argusanalyzer.com").strip(),
        "from_name": os.getenv("SMTP_FROM_NAME", "ARGUS Security").strip(),
        "use_tls": os.getenv("SMTP_USE_TLS", "1").lower() in ("1", "true", "yes"),
    }


def _smtp_is_configured() -> bool:
    cfg = _smtp_config()
    return bool(cfg["host"] and cfg["user"] and cfg["password"])


# ─── Templates HTML d'email ─────────────────────────────────────────

def _wrap_html(title: str, body_html: str, cta_label: str = "", cta_url: str = "") -> str:
    """Enveloppe un contenu HTML dans le template visuel ARGUS."""
    cta_block = ""
    if cta_label and cta_url:
        cta_block = f"""
        <div style="text-align:center;margin:32px 0;">
          <a href="{cta_url}" style="display:inline-block;background:linear-gradient(135deg,#00d9ff,#0099cc);color:#fff;padding:14px 28px;border-radius:10px;text-decoration:none;font-family:'Inter',sans-serif;font-weight:600;font-size:15px;">{cta_label}</a>
        </div>"""

    return f"""<!DOCTYPE html>
<html lang="fr">
<head><meta charset="utf-8"><title>{title}</title></head>
<body style="margin:0;padding:0;background:#f5f6f8;font-family:-apple-system,BlinkMacSystemFont,'Inter',sans-serif;color:#1a1f2e;">
  <table cellpadding="0" cellspacing="0" border="0" width="100%" style="background:#f5f6f8;padding:32px 16px;">
    <tr><td align="center">
      <table cellpadding="0" cellspacing="0" border="0" width="560" style="max-width:560px;background:#fff;border-radius:14px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,0.06);">
        <!-- Header -->
        <tr><td style="background:#0a0e1a;padding:24px 32px;">
          <div style="font-size:22px;font-weight:800;color:#00d9ff;letter-spacing:1px;">
            <svg viewBox="0 0 100 100" width="22" height="22" style="vertical-align:middle;margin-right:6px;display:inline-block;">
              <circle cx="50" cy="50" r="28" fill="none" stroke="#00d9ff" stroke-width="3"/>
              <circle cx="50" cy="50" r="15" fill="none" stroke="#00d9ff" stroke-width="2"/>
              <circle cx="50" cy="50" r="6" fill="#b06aff"/>
              <line x1="50" y1="4" x2="50" y2="18" stroke="#00d9ff" stroke-width="3" stroke-linecap="round"/>
              <line x1="50" y1="82" x2="50" y2="96" stroke="#00d9ff" stroke-width="3" stroke-linecap="round"/>
              <line x1="4" y1="50" x2="18" y2="50" stroke="#00d9ff" stroke-width="3" stroke-linecap="round"/>
              <line x1="82" y1="50" x2="96" y2="50" stroke="#00d9ff" stroke-width="3" stroke-linecap="round"/>
            </svg>ARGUS
          </div>
          <div style="font-size:11px;color:#8b9cad;text-transform:uppercase;letter-spacing:1.5px;margin-top:2px;">Security by Exasys</div>
        </td></tr>
        <!-- Body -->
        <tr><td style="padding:36px 32px;">
          <h1 style="font-size:22px;font-weight:700;color:#0a0e1a;margin:0 0 16px;">{title}</h1>
          <div style="font-size:15px;line-height:1.6;color:#333;">{body_html}</div>
          {cta_block}
        </td></tr>
        <!-- Footer -->
        <tr><td style="background:#fafbfc;padding:20px 32px;border-top:1px solid #e8eaed;font-size:12px;color:#8b9cad;text-align:center;">
          ARGUS by Exasys · Experts en cybersécurité depuis 2015<br>
          Données chiffrées · Jamais revendues
        </td></tr>
      </table>
    </td></tr>
  </table>
</body></html>"""


def _save_to_disk(to: str, subject: str, html: str) -> Path:
    """Sauvegarde l'email sur disque (mode dev)."""
    out_dir = Path(__file__).resolve().parent.parent / "logs" / "emails"
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S_%f")
    safe_to = to.replace("@", "_at_").replace(".", "_")
    path = out_dir / f"{ts}_{safe_to}.html"
    with open(path, "w", encoding="utf-8") as f:
        f.write(f"<!-- À : {to} -->\n<!-- Sujet : {subject} -->\n\n{html}")
    return path


def send_email(to: str, subject: str, html: str, text_fallback: str = "") -> bool:
    """
    Envoie un email. Retourne True si succès (ou sauvegarde dev).
    Ne bloque jamais le flow utilisateur en cas d'échec SMTP — log seulement.
    """
    if not _smtp_is_configured():
        # Mode dev : on sauvegarde sur disque + console
        path = _save_to_disk(to, subject, html)
        print(f"[EMAIL DEV] → {to} | {subject} | preview: {path}", flush=True)
        return True

    cfg = _smtp_config()
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = f"{cfg['from_name']} <{cfg['from_email']}>"
    msg["To"] = to

    if text_fallback:
        msg.attach(MIMEText(text_fallback, "plain", "utf-8"))
    msg.attach(MIMEText(html, "html", "utf-8"))

    try:
        if cfg["use_tls"]:
            ctx = ssl.create_default_context()
            with smtplib.SMTP(cfg["host"], cfg["port"], timeout=15) as srv:
                srv.starttls(context=ctx)
                srv.login(cfg["user"], cfg["password"])
                srv.send_message(msg)
        else:
            with smtplib.SMTP_SSL(cfg["host"], cfg["port"], timeout=15) as srv:
                srv.login(cfg["user"], cfg["password"])
                srv.send_message(msg)
        print(f"[EMAIL] → {to} | {subject} | OK", flush=True)
        return True
    except Exception as e:
        # On log mais on ne bloque PAS le flow user — l'email sera réessayé manuellement
        print(f"[EMAIL ERROR] → {to} | {subject} | {e}", flush=True)
        # Fallback : sauvegarde sur disque pour pouvoir le ré-envoyer plus tard
        try:
            _save_to_disk(to, subject, html)
        except Exception:
            pass
        return False


# ─── Templates métier ───────────────────────────────────────────────

def send_welcome_email(to: str, name: str, base_url: str) -> bool:
    """Email de bienvenue à l'inscription."""
    title = f"Bienvenue sur ARGUS, {name.split(' ')[0]}"
    body = f"""
    <p>Votre compte ARGUS Security est créé. Vous pouvez dès maintenant analyser
    la surface d'attaque de vos domaines en moins de 60 secondes.</p>

    <p><strong>Vos avantages avec le plan Gratuit :</strong></p>
    <ul style="padding-left:20px;line-height:1.8;">
      <li>Scans illimités</li>
      <li>Aperçu de votre exposition (20% des résultats)</li>
      <li>Score de risque A-F clair</li>
      <li>Aucune carte bancaire requise</li>
    </ul>

    <p>Pour débloquer 100% des résultats, l'export PDF et l'audit complet,
    passez au plan <strong>Essentiel (29€/mois)</strong> — sans engagement.</p>
    """
    cta_url = f"{base_url}/"
    html = _wrap_html(title, body, "Lancer mon premier scan →", cta_url)
    text = f"""Bienvenue sur ARGUS, {name} !

Votre compte est créé. Lancez votre premier scan : {cta_url}

À bientôt,
L'équipe ARGUS Security
"""
    return send_email(to, "Bienvenue sur ARGUS Security", html, text)


def send_password_reset_email(to: str, name: str, reset_url: str) -> bool:
    """Email de réinitialisation de mot de passe."""
    title = "Réinitialisez votre mot de passe"
    body = f"""
    <p>Bonjour {name.split(' ')[0] if name else ''},</p>

    <p>Vous avez demandé à réinitialiser le mot de passe de votre compte ARGUS Security.
    Cliquez sur le bouton ci-dessous pour choisir un nouveau mot de passe.</p>

    <p style="color:#666;font-size:13px;">
      Ce lien est valable <strong>1 heure</strong> et ne peut être utilisé qu'une seule fois.
    </p>

    <p style="color:#666;font-size:13px;margin-top:20px;">
      Si vous n'êtes pas à l'origine de cette demande, vous pouvez ignorer cet email —
      votre mot de passe restera inchangé.
    </p>
    """
    html = _wrap_html(title, body, "Réinitialiser mon mot de passe", reset_url)
    text = f"""Réinitialisation de mot de passe ARGUS

Cliquez sur ce lien pour choisir un nouveau mot de passe (valable 1 heure) :
{reset_url}

Si vous n'avez pas demandé ceci, ignorez cet email.

L'équipe ARGUS Security
"""
    return send_email(to, "Réinitialisation de votre mot de passe ARGUS", html, text)


def send_email_verification(to: str, name: str, verify_url: str) -> bool:
    """Email envoyé à l'inscription pour vérifier l'adresse email."""
    title = "Confirmez votre adresse email"
    body = f"""
    <p>Bonjour {name.split(' ')[0] if name else ''},</p>

    <p>Bienvenue sur ARGUS Security ! Pour activer votre compte et commencer à analyser
    votre surface d'attaque, confirmez simplement votre adresse email en cliquant
    sur le bouton ci-dessous.</p>

    <p style="color:#666;font-size:13px;margin-top:20px;">
      Ce lien est valable <strong>24 heures</strong>.
      Tant que votre email n'est pas vérifié, vous ne pouvez pas lancer de scan.
    </p>

    <p style="color:#666;font-size:13px;">
      Si vous n'êtes pas à l'origine de cette inscription, ignorez cet email.
    </p>
    """
    html = _wrap_html(title, body, "Confirmer mon email", verify_url)
    text = f"""Confirmez votre email ARGUS Security

Cliquez sur ce lien pour confirmer votre email (valable 24h) :
{verify_url}

Si vous n'êtes pas à l'origine de cette inscription, ignorez cet email.

L'équipe ARGUS Security
"""
    return send_email(to, "Confirmez votre email — ARGUS Security", html, text)


def send_sales_contact_email(sales_to: str, prospect: dict) -> bool:
    """
    Notifie l'équipe commerciale qu'un prospect a demandé un devis pour le plan Pro.
    `prospect` doit contenir : name, email, phone, company, company_size, message.
    """
    title = "Nouvelle demande d'audit — Plan Entreprise"
    rows = [
        ("Nom", prospect.get("name", "")),
        ("Email", prospect.get("email", "")),
        ("Téléphone", prospect.get("phone", "") or "—"),
        ("Entreprise", prospect.get("company", "") or "—"),
        ("Taille", prospect.get("company_size", "") or "—"),
    ]
    rows_html = "".join(
        f'<tr><td style="padding:8px 12px;color:#666;font-size:13px;width:30%;">{k}</td>'
        f'<td style="padding:8px 12px;color:#1a1f2e;font-size:14px;font-weight:600;">{v}</td></tr>'
        for k, v in rows
    )
    msg = (prospect.get("message", "") or "").replace("\n", "<br>")
    body = f"""
    <p>Un prospect vient de réserver un <strong>audit gratuit</strong> dans le cadre du plan <strong>Entreprise</strong>.</p>

    <table style="width:100%;border-collapse:collapse;background:#fafbfc;border-radius:8px;margin:20px 0;">
      {rows_html}
    </table>

    <p style="font-size:13px;color:#666;margin-bottom:6px;">Message :</p>
    <div style="background:#fafbfc;border-left:3px solid #00d9ff;padding:14px 16px;border-radius:0 8px 8px 0;font-size:14px;line-height:1.6;color:#333;">
      {msg or '<em style="color:#999;">(aucun message)</em>'}
    </div>

    <p style="margin-top:24px;font-size:13px;color:#666;">
      → Répondre directement au prospect :
      <a href="mailto:{prospect.get('email', '')}" style="color:#00d9ff;font-weight:600;">{prospect.get('email', '')}</a>
    </p>
    """
    html = _wrap_html(title, body)
    return send_email(sales_to, f"[Sales] Audit Entreprise — {prospect.get('name', 'Anonyme')}", html)


def send_sales_autoreply_email(to: str, name: str) -> bool:
    """Auto-reply au prospect qui vient de soumettre une demande Pro."""
    title = "Audit réservé — On vous recontacte"
    first_name = (name.split(" ")[0] if name else "").strip() or "bonjour"
    body = f"""
    <p>Bonjour {first_name},</p>

    <p>Merci d'avoir réservé un <strong>audit gratuit</strong> dans le cadre du plan
    <strong>Entreprise</strong> d'ARGUS Security.</p>

    <p>Nos experts Exasys étudient votre contexte et reviendront vers vous sous
    <strong>24h ouvrées</strong> pour planifier l'audit et préparer un partenariat
    adapté à votre infrastructure.</p>

    <p>En attendant, vous pouvez :</p>
    <ul style="padding-left:20px;line-height:1.8;">
      <li>Lancer un scan gratuit pour découvrir votre surface d'attaque</li>
      <li>Essayer le plan Essentiel (29€/mois, sans engagement)</li>
      <li>Nous écrire directement à <a href="mailto:contact@argusanalyzer.com" style="color:#00d9ff;">contact@argusanalyzer.com</a></li>
    </ul>

    <p style="margin-top:24px;color:#666;font-size:13px;">
      À très vite,<br>L'équipe Exasys
    </p>
    """
    html = _wrap_html(title, body)
    return send_email(to, "Audit ARGUS Entreprise réservé — On vous recontacte", html)


def send_plan_activated_email(to: str, name: str, plan_label: str, base_url: str) -> bool:
    """Email envoyé après activation d'un plan payant."""
    title = f"Votre plan {plan_label} est activé"
    body = f"""
    <p>Bonjour {name.split(' ')[0] if name else ''},</p>

    <p>Votre plan <strong>{plan_label}</strong> est désormais actif.
    Toutes les fonctionnalités sont disponibles immédiatement dans votre espace.</p>

    <p>Un reçu de paiement vous sera envoyé séparément.</p>

    <p style="color:#666;font-size:13px;margin-top:20px;">
      Pour gérer votre abonnement ou télécharger vos factures,
      rendez-vous dans votre espace compte.
    </p>
    """
    cta_url = f"{base_url}/account"
    html = _wrap_html(title, body, "Accéder à mon compte →", cta_url)
    return send_email(to, f"Plan {plan_label} activé · ARGUS Security", html)
