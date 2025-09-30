from sqlalchemy import Boolean, Column, Integer, String, DateTime, Text, sql, Float, JSON
from app.database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    first_name = Column(Text)
    last_name = Column(Text)
    username = Column(Text, unique=True, nullable=False)
    email = Column(Text, unique=True, nullable=False)
    password_hash = Column(Text, nullable=False)
    gender = Column(Text)
    is_active = Column(Boolean, default=True)
    is_superuser = Column(Boolean, default=False)
    is_admin = Column(Boolean, default=False)
    created_at = Column(DateTime, server_default=sql.func.now())


class AIAnalysisResult(Base):
    __tablename__ = "ai_analysis_results"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, nullable=False)  # Foreign key to users table
    apk_name = Column(String(500), nullable=False)
    file_size = Column(Integer)
    prediction = Column(String(50), nullable=False)  # 'malware', 'benign', 'error'
    confidence = Column(Float, nullable=False)
    active_features_count = Column(Integer, default=0)
    total_features = Column(Integer, default=215)
    active_features = Column(JSON)  # List of active feature names
    feature_summary = Column(JSON)  # Detailed feature analysis
    model_info = Column(JSON)  # Model information used for prediction
    analysis_timestamp = Column(DateTime, server_default=sql.func.now())
    error_message = Column(Text)  # Error details if prediction failed
    scan_id = Column(String(100))  # Link to file analysis scan
