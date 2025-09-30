

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.routers import auth, admin, analysis
from sqlalchemy import text
from sqlalchemy.exc import ProgrammingError
from app.database import Base, engine, SessionLocal
from app.services.auth import hash_password
from app.models import User, AIAnalysisResult  # Import models for database initialization
import os

app = FastAPI(
    title="Matrisks API",
    description="API for Matrisks platform",
    version="0.1.0"
)

# Configure CORS
default_local_origins = [
    "http://localhost",
    "https://localhost",
    "http://127.0.0.1",
    "https://127.0.0.1",
]

extra_origins = [origin.strip() for origin in os.environ.get("CORS_ORIGINS", "").split(",") if origin.strip()]

allow_origins = []

# Include explicit ports for common local development setups
for base_origin in default_local_origins:
    allow_origins.extend([
        f"{base_origin}:5173",
        f"{base_origin}:5174",
        f"{base_origin}:4173",
    ])

allow_origins.extend(default_local_origins)
allow_origins.extend(extra_origins)

app.add_middleware(
    CORSMiddleware,
    allow_origins=allow_origins,
    allow_origin_regex=r"https?://(localhost|127\.0\.0\.1)(:\d+)?",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(auth.router)
app.include_router(admin.router)
app.include_router(analysis.router)

# Root endpoint
@app.get("/")
async def root():
    return {"message": "Welcome to Matrisks API"}


@app.get("/health")
async def health_check():
    """Simple health check endpoint for uptime probes."""
    return {"status": "ok"}

@app.on_event("startup")
def on_startup():
    # Ensure tables exist (first-time setup). In production, prefer Alembic migrations.
    Base.metadata.create_all(bind=engine)

    # Create default superuser if not exists
    admin_email = os.environ.get("ADMIN_EMAIL", "admin@example.com")
    admin_username = os.environ.get("ADMIN_USERNAME", "admin")
    admin_password = os.environ.get("ADMIN_PASSWORD", "admin123")

    db = SessionLocal()
    try:
        # Verify users table exists (safety)
        try:
            db.execute(text("SELECT 1 FROM users LIMIT 1"))
        except ProgrammingError:
            db.rollback()
            Base.metadata.create_all(bind=engine)

        existing = db.execute(
            text("SELECT id FROM users WHERE email=:email OR username=:username LIMIT 1"),
            {"email": admin_email, "username": admin_username}
        ).first()

        if not existing:
            password_hash = hash_password(admin_password)
            db.execute(text(
                """
                INSERT INTO users (email, username, password_hash, first_name, last_name, is_active, is_superuser)
                VALUES (:email, :username, :password_hash, :first_name, :last_name, true, true)
                """
            ), {
                "email": admin_email,
                "username": admin_username,
                "password_hash": password_hash,
                "first_name": os.environ.get("ADMIN_FIRST_NAME", "Admin"),
                "last_name": os.environ.get("ADMIN_LAST_NAME", "User"),
            })
            db.commit()
    finally:
        db.close()
