import json
import bcrypt
from datetime import datetime, timezone
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

# Database connection
DATABASE_URL = "postgresql://matrisksuser:admin123@localhost:5432/matrisks"
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Sample local storage data (replace with your actual data)
# This is an example - you'll need to get the actual data from your browser's local storage
local_users = [
    {
        "email": "user1@example.com",
        "username": "user1",
        "password": "password123",  # This should be hashed in production
        "first_name": "User",
        "last_name": "One",
        "is_active": True
    },
    # Add more users as needed
]

def hash_password(password: str) -> str:
    """Hash a password for storing."""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def migrate_users():
    db = SessionLocal()
    
    for user_data in local_users:
        # Check if user already exists
        result = db.execute(
            text("SELECT id FROM users WHERE email = :email"),
            {"email": user_data["email"]}
        ).fetchone()
        
        if not result:
            try:
                # Hash the password
                hashed_password = hash_password(user_data["password"])
                
                # Insert the user
                db.execute(
                    text("""
                        INSERT INTO users (email, username, password_hash, first_name, last_name, is_active, created_at)
                        VALUES (:email, :username, :password_hash, :first_name, :last_name, :is_active, :created_at)
                    """),
                    {
                        "email": user_data["email"],
                        "username": user_data.get("username", user_data["email"].split('@')[0]),
                        "password_hash": hashed_password,
                        "first_name": user_data.get("first_name", ""),
                        "last_name": user_data.get("last_name", ""),
                        "is_active": user_data.get("is_active", True),
                        "created_at": datetime.now(timezone.utc)
                    }
                )
                print(f"Migrated user: {user_data['email']}")
            except Exception as e:
                print(f"Error migrating user {user_data['email']}: {e}")
                db.rollback()
        else:
            print(f"User {user_data['email']} already exists")
    
    db.commit()
    db.close()

if __name__ == "__main__":
    print("Starting user migration...")
    migrate_users()
    print("Migration completed. Check the output for any errors.")

