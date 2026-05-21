"""
auth.py — Authentification ARGUS

Gère :
- Hachage des mots de passe (bcrypt)
- Récupération de l'utilisateur depuis la session
- Helpers require_user / require_admin
"""

import os
import bcrypt
from typing import Optional
from fastapi import Request
from sqlalchemy.orm import Session

from app.models import User, PLAN_LIMITS

# Email admin défini dans .env
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "")


def hash_password(password: str) -> str:
    """Transforme un mot de passe en hash bcrypt sécurisé (non réversible)."""
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")


def verify_password(password: str, hashed: str) -> bool:
    """Vérifie qu'un mot de passe correspond à son hash bcrypt."""
    try:
        return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False


def get_current_user(request: Request, db: Session) -> Optional[User]:
    """Retourne l'utilisateur connecté (ou None si pas connecté)."""
    user_id = request.session.get("user_id")
    if not user_id:
        return None
    return db.query(User).filter(User.id == user_id).first()


def get_plan_limits(user: Optional[User]) -> dict:
    """Retourne les droits du plan de l'utilisateur (ou free si non connecté)."""
    if not user:
        return PLAN_LIMITS["free"]
    return PLAN_LIMITS.get(user.plan, PLAN_LIMITS["free"])


def can_see_full_results(user: Optional[User]) -> bool:
    """Renvoie True si l'utilisateur a accès aux résultats complets."""
    limits = get_plan_limits(user)
    return limits["full_results"] or (user is not None and user.is_admin)
