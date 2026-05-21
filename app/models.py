"""
models.py — Tables de la base de données SQLite ARGUS

Sprint 3 ajoute :
  - User (auth, plan, WhatsApp opt-in)
  - user_id (nullable) sur Scan pour lier chaque scan à un utilisateur
"""

from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, Text, ForeignKey, JSON, Float, Boolean
from sqlalchemy.orm import relationship

from app.database import Base


# ─── Plans ARGUS — droits par niveau ────────────────────────────────
PLAN_LIMITS = {
    "free":      {"full_results": False, "pentest": False, "ai_brief": False, "export": False},
    "essentiel": {"full_results": True,  "pentest": False, "ai_brief": True,  "export": True},
    "pro":       {"full_results": True,  "pentest": True,  "ai_brief": True,  "export": True},
    "agency":    {"full_results": True,  "pentest": True,  "ai_brief": True,  "export": True},
}

PLAN_NAMES = {
    "free":      "Gratuit",
    "essentiel": "Essentiel — 29€/mois",
    "pro":       "Pro — 79€/mois",
    "agency":    "Agency — 249€/mois",
}


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    name = Column(String(255), nullable=True)
    company = Column(String(255), nullable=True)

    # Plan & billing
    plan = Column(String(20), default="free")       # free | essentiel | pro | agency
    plan_expires_at = Column(DateTime, nullable=True)

    # Contact WhatsApp (optionnel, opt-in)
    phone_whatsapp = Column(String(50), nullable=True)
    whatsapp_opt_in = Column(Boolean, default=False)

    # Avatar (data URL base64 ou chemin vers /static/avatars/X.jpg)
    avatar_url = Column(String(500), nullable=True)

    # Stripe (pour billing)
    stripe_customer_id = Column(String(80), nullable=True)
    stripe_subscription_id = Column(String(80), nullable=True)

    # Admin
    is_admin = Column(Boolean, default=False)

    # CGU — horodatées pour audit légal
    tos_accepted = Column(Boolean, default=False)
    tos_accepted_at = Column(DateTime, nullable=True)

    # Vérification d'email (token envoyé à l'inscription, expire après 24h)
    email_verified_at = Column(DateTime, nullable=True)

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login_at = Column(DateTime, nullable=True)

    # Relations
    scans = relationship("Scan", back_populates="user")
    password_reset_tokens = relationship("PasswordResetToken", back_populates="user",
                                          cascade="all, delete-orphan")


class PasswordResetToken(Base):
    """Token unique pour reset de mot de passe — expire après 1h."""
    __tablename__ = "password_reset_tokens"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    token = Column(String(128), unique=True, nullable=False, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)
    used_at = Column(DateTime, nullable=True)

    user = relationship("User", back_populates="password_reset_tokens")


class EmailVerificationToken(Base):
    """Token unique pour vérification d'email — expire après 24h."""
    __tablename__ = "email_verification_tokens"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    token = Column(String(128), unique=True, nullable=False, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)
    used_at = Column(DateTime, nullable=True)

    user = relationship("User", backref="email_verification_tokens")


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, autoincrement=True)
    domain = Column(String(255), nullable=False, index=True)
    status = Column(String(20), default="running")  # running | completed | failed
    started_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)

    # Lien utilisateur (nullable = scans existants sans compte)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)

    # Compteurs
    assets_count = Column(Integer, default=0)
    alive_count = Column(Integer, default=0)
    vulns_count = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    kev_count = Column(Integer, default=0)

    # ARGUS Risk Score
    risk_score = Column(Integer, default=100)
    risk_grade = Column(String(1), default="A")
    risk_breakdown = Column(JSON, default=list)

    # DNS / Email security
    dns_records = Column(JSON, default=dict)
    spf = Column(JSON, default=dict)
    dmarc = Column(JSON, default=dict)
    dkim = Column(JSON, default=dict)
    dns_issues = Column(JSON, default=list)

    # Analyse de sécurité (générée par notre moteur)
    ai_summary = Column(Text, nullable=True)

    # Erreur si failed
    error_message = Column(Text, nullable=True)

    # Sources de découverte
    discovery_sources = Column(JSON, default=dict)
    discovered_subs = Column(JSON, default=list)

    # Progress tracker
    progress = Column(Integer, default=0)
    current_step = Column(String(255), default="Initialisation")
    current_detail = Column(String(500), default="")

    # Pentest : consentement légal (audit trail)
    pentest_authorized = Column(Boolean, default=False)
    pentest_authorization_text = Column(Text, nullable=True)
    pentest_authorized_at = Column(DateTime, nullable=True)
    pentest_findings = Column(JSON, default=dict)

    # Relations
    user = relationship("User", back_populates="scans")
    assets = relationship("Asset", back_populates="scan", cascade="all, delete-orphan")
    vulns = relationship("Vuln", back_populates="scan", cascade="all, delete-orphan")
    tls_findings = relationship("TlsFinding", back_populates="scan", cascade="all, delete-orphan")


class Asset(Base):
    __tablename__ = "assets"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)

    url = Column(String(500), nullable=False)
    host = Column(String(255), nullable=False)
    status_code = Column(Integer, default=0)
    title = Column(String(500), nullable=True)
    webserver = Column(String(100), nullable=True)
    content_length = Column(Integer, default=0)
    tech = Column(JSON, default=list)

    scan = relationship("Scan", back_populates="assets")
    vulns = relationship("Vuln", back_populates="asset")


class Vuln(Base):
    __tablename__ = "vulns"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=True)

    template_id = Column(String(255), nullable=False)
    name = Column(String(500), nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(String(20), default="info")
    matched_url = Column(String(500), nullable=True)

    # Enrichissement EPSS + KEV
    cve_id = Column(String(50), nullable=True)
    epss_score = Column(Float, nullable=True)
    epss_percentile = Column(Float, nullable=True)
    kev = Column(Boolean, default=False)

    reference = Column(JSON, default=list)
    extracted_results = Column(JSON, default=list)
    tags = Column(JSON, default=list)

    scan = relationship("Scan", back_populates="vulns")
    asset = relationship("Asset", back_populates="vulns")


class TlsFinding(Base):
    """Audit TLS/SSL pour un host."""
    __tablename__ = "tls_findings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)

    host = Column(String(255), nullable=False)
    port = Column(Integer, default=443)
    issuer = Column(String(500), nullable=True)
    subject_cn = Column(String(500), nullable=True)
    subject_an = Column(JSON, default=list)
    not_before = Column(String(50), nullable=True)
    not_after = Column(String(50), nullable=True)
    days_until_expiry = Column(Integer, nullable=True)
    tls_versions = Column(JSON, default=list)
    cipher = Column(String(255), nullable=True)
    self_signed = Column(Boolean, default=False)
    expired = Column(Boolean, default=False)
    mismatched = Column(Boolean, default=False)
    issues = Column(JSON, default=list)

    scan = relationship("Scan", back_populates="tls_findings")


