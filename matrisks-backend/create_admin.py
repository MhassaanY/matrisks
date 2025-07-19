import sys
from datetime import datetime, timezone
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
import bcrypt

# Database connection - update with your actual credentials
DATABASE_URL = "postgresql://matrisksuser:admin123@localhost:5432/matrisks"
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Create a new session
db = SessionLocal()

# Admin user details
email = "admin@example.com"
username = "admin"
password = "admin123"  # Change this to a strong password in production
first_name = "Admin"
last_name = "User"

# Hash the password
password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

# SQL to insert the admin user
sql = text("""
    INSERT INTO users (email, username, password_hash, first_name, last_name, is_active, created_at)
    VALUES (:email, :username, :password_hash, :first_name, :last_name, :is_active, :created_at)
""")

try:
    # Execute the SQL with parameters
    db.execute(sql, {
        'email': email,
        'username': username,
        'password_hash': password_hash,
        'first_name': first_name,
        'last_name': last_name,
        'is_active': True,
        'created_at': datetime.now(timezone.utc)
    })
    db.commit()
    print(f"Admin user created successfully with email: {email}")
    print(f"Password: {password}")  # Only for development!
except Exception as e:
    db.rollback()
    print(f"Error creating admin user: {e}")
    raise  # This will show the full traceback
finally:
    db.close()
