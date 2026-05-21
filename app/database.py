"""
database.py — Configuration de la base de données SQLite

SQLite = base de données dans UN SEUL FICHIER (data/pupelmet.db).
(= comme un Excel mais avec du SQL et bien plus rapide. Zéro install,
 zéro serveur à démarrer. Parfait pour un MVP local.)

SQLAlchemy = bibliothèque Python qui mappe nos classes Python sur des tables SQL.
(= au lieu d'écrire "INSERT INTO scans VALUES (...)" en SQL brut,
 on fait `session.add(Scan(domain="x"))` en Python. Plus lisible, moins d'erreurs.)
"""

from pathlib import Path
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

# Chemin absolu vers le fichier .db (créé automatiquement au premier lancement)
ROOT = Path(__file__).parent.parent
DB_PATH = ROOT / "data" / "pupelmet.db"
DB_PATH.parent.mkdir(exist_ok=True)

# "engine" = la connexion physique à la base de données
# (= équivalent du "câble réseau" entre Python et SQLite)
DATABASE_URL = f"sqlite:///{DB_PATH}"
engine = create_engine(
    DATABASE_URL,
    echo=False,  # True pour voir toutes les requêtes SQL dans le terminal (debug)
    connect_args={"check_same_thread": False},  # SQLite + multi-thread FastAPI
)

# Base = classe parente de tous nos "modèles" (= tables)
Base = declarative_base()

# Session = "panier" pour grouper des opérations DB et les valider d'un coup
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


def get_db():
    """
    "Dependency" FastAPI : ouvre une session DB pour chaque requête HTTP,
    la ferme à la fin (même si erreur). Évite les fuites de connexion.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """Crée toutes les tables si elles n'existent pas. À appeler au démarrage."""
    # Import nécessaire pour que Base "voie" les modèles avant create_all()
    from app import models  # noqa: F401
    Base.metadata.create_all(bind=engine)
