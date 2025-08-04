from sqlalchemy import create_engine, text
from sqlalchemy.exc import SQLAlchemyError

DATABASE_URL = "sqlite:///./vault.db"

engine = create_engine(
    DATABASE_URL, connect_args={"check_same_thread": False}
)

def check_database() -> bool:
    """Return True if the database is reachable."""
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        return True
    except SQLAlchemyError:
        return False
