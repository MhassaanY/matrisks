import json
import bcrypt
from datetime import datetime, timezone
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

# Database connection
DATABASE_URL = "postgresql://matrisksuser:admin123@localhost:5432/matrisks"
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Mock users from localStorage
mock_users_json = """
[{
  "id": 1,
  "first_name": "Mat",
  "last_name": "Risk",
  "username": "MatRisks",
  "email": "mdhassaany@gmail.com",
  "gender": "Male",
  "password_hash": "motherFucker1",
  "is_active": true,
  "created_at": "2025-05-23T20:42:46.523Z"
}, {
  "id": 2,
  "first_name": "zinger",
  "last_name": "burger",
  "username": "ZingerBurger",
  "email": "chiefgaladon5@gmail.com",
  "gender": "Male",
  "password_hash": "motherFucker2",
  "is_active": true,
  "created_at": "2025-05-24T21:05:43.656Z"
}, {
  "id": 3,
  "first_name": "Mat",
  "last_name": "Risk",
  "username": "MatRisks1",
  "email": "hassaantariq666@gmail.com",
  "gender": "Male",
  "password_hash": "motherFucker1",
  "is_active": false,
  "email_verified": false,
  "verification_token": "kd7a8r1j87",
  "created_at": "2025-05-24T22:11:42.957Z"
}]
"""

def hash_password(password: str) -> str:
    """Hash a password for storing."""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def migrate_mock_users():
    mock_users = json.loads(mock_users_json)
    db = SessionLocal()
    
    for user_data in mock_users:
        # Check if user already exists
        result = db.execute(
            text("SELECT id FROM users WHERE email = :email"),
            {"email": user_data["email"]}
        ).fetchone()
        
        if not result:
            try:
                # Hash the password (using the mock password)
                hashed_password = hash_password(user_data["password_hash"])
                
                # Insert the user
                db.execute(
                    text("""
                        INSERT INTO users (email, username, password_hash, first_name, last_name, gender, is_active, created_at)
                        VALUES (:email, :username, :password_hash, :first_name, :last_name, :gender, :is_active, :created_at)
                    """),
                    {
                        "email": user_data["email"],
                        "username": user_data["username"],
                        "password_hash": hashed_password,
                        "first_name": user_data.get("first_name", ""),
                        "last_name": user_data.get("last_name", ""),
                        "gender": user_data.get("gender", "Other"),
                        "is_active": user_data.get("is_active", True),
                        "created_at": datetime.fromisoformat(user_data["created_at"].replace('Z', '+00:00'))
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
    print("Migration completed.")

if __name__ == "__main__":
    print("Starting mock users migration...")
    migrate_mock_users()
