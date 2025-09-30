"""
AI Malware Detection Service

Provides AI-powered malware detection analysis integrated with Matrisks backend.
"""
import os
import sys
import json
import logging
import tempfile
import traceback
from typing import Dict, Any, Optional, List, Tuple
from datetime import datetime

from sqlalchemy.orm import Session
from app.database import SessionLocal
from app.models import AIAnalysisResult


class AIAnalysisService:
    """Service for AI-powered malware detection analysis"""
    
    def __init__(self):
        """Initialize AI analysis service with predictor"""
        self.logger = logging.getLogger(__name__)
        self.predictor = None
        try:
            # Import the AI predictor with correct path
            ai_module_path = '/home/zain/matrisks/ai_based_malware_detection'
            sys.path.insert(0, ai_module_path)
            from predict import MalwarePredictor
            
            # Initialize with model directory
            model_dir = os.path.join(ai_module_path, 'model')
            self.predictor = MalwarePredictor(model_dir)
            self.logger.info("AI Malware Detection service initialized successfully")
        except Exception as e:
            self.logger.error(f"Failed to initialize AI predictor: {e}")
            self.predictor = None

    def is_available(self) -> bool:
        """Check if AI service is available and functional"""
        return self.predictor is not None

    def get_model_info(self) -> Dict[str, Any]:
        """Get information about the AI model"""
        if not self.is_available():
            return {
                "available": False,
                "error": "AI predictor not initialized"
            }
        
        try:
            # Use the predictor's method instead of importing standalone function
            info = self.predictor.get_model_info()
            return {
                "available": True,
                "model_type": info.get("model_type", "RandomForestClassifier"),
                "feature_count": info.get("feature_count", 215),
                "model_loaded": True
            }
        except Exception as e:
            self.logger.error(f"Error getting model info: {e}")
            return {
                "available": True,
                "model_type": "RandomForestClassifier", 
                "feature_count": 215,
                "model_loaded": True,
                "note": "Using default info due to error"
            }

    def analyze_apk(self, apk_path: str, user_id: int, apk_name: str, scan_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Analyze APK file using AI malware detection
        
        Args:
            apk_path: Path to APK file to analyze
            user_id: ID of user requesting analysis  
            apk_name: Name of APK file
            scan_id: Optional scan ID for tracking
            
        Returns:
            Dictionary containing analysis results
        """
        if not self.is_available():
            error_msg = "AI malware detection service is not available"
            self.logger.error(error_msg)
            return {
                "success": False,
                "error": error_msg,
                "prediction": "error"
            }

        try:
            # Perform AI analysis
            self.logger.info(f"Starting AI analysis for APK: {apk_name}")
            result = self.predictor.predict(apk_path)
            
            # Get file size
            file_size = os.path.getsize(apk_path) if os.path.exists(apk_path) else 0
            
            # Extract feature information from the result structure
            feature_summary = result.get("feature_summary", {})
            active_features_count = feature_summary.get("active_features", 0)
            total_features = feature_summary.get("total_features", 215)
            
            # Prepare analysis result
            analysis_result = {
                "success": True,
                "prediction": result["prediction"],
                "confidence": result["confidence"], 
                "risk_level": self._get_risk_level(result["prediction"], result["confidence"]),
                "active_features": active_features_count,
                "total_features": total_features,
                "feature_analysis": feature_summary,
                "model_info": self.get_model_info(),
                "timestamp": datetime.now().isoformat(),
                "file_size": file_size,
                "apk_name": result.get("apk_name", apk_name)
            }
            
            # Save to database
            db_result = self.save_analysis_result(
                user_id=user_id,
                apk_name=apk_name,
                file_size=file_size,
                prediction=result["prediction"],
                confidence=result["confidence"],
                active_features_count=active_features_count,
                active_features=feature_summary,
                scan_id=scan_id
            )
            
            if db_result:
                analysis_result["analysis_id"] = db_result.id
            
            self.logger.info(f"AI analysis completed for {apk_name}: {result['prediction']} ({result['confidence']:.2f})")
            return analysis_result
            
        except Exception as e:
            error_msg = f"Error during AI analysis: {str(e)}"
            self.logger.error(f"{error_msg}\n{traceback.format_exc()}")
            
            # Save error to database
            self.save_analysis_result(
                user_id=user_id,
                apk_name=apk_name,
                prediction="error",
                confidence=0.0,
                error_message=error_msg,
                scan_id=scan_id
            )
            
            return {
                "success": False,
                "error": error_msg,
                "prediction": "error"
            }

    def _get_risk_level(self, prediction: str, confidence: float) -> str:
        """Determine risk level based on prediction and confidence"""
        if prediction == "malware":
            if confidence >= 0.8:
                return "high"
            elif confidence >= 0.6:
                return "medium"
            else:
                return "low"
        else:
            return "low"

    def save_analysis_result(self, user_id: int, apk_name: str, prediction: str, 
                           confidence: float, file_size: Optional[int] = None,
                           active_features_count: int = 0, active_features: Optional[Dict] = None,
                           error_message: Optional[str] = None, scan_id: Optional[str] = None) -> Optional[AIAnalysisResult]:
        """Save analysis result to database"""
        db = SessionLocal()
        try:
            # Prepare feature summary
            feature_summary = {}
            if active_features:
                feature_summary = {
                    "active_count": active_features_count,
                    "total_count": 215,
                    "percentage": (active_features_count / 215) * 100 if active_features_count else 0
                }
            
            # Create database record
            result = AIAnalysisResult(
                user_id=user_id,
                apk_name=apk_name,
                file_size=file_size,
                prediction=prediction,
                confidence=confidence,
                active_features_count=active_features_count,
                total_features=215,
                active_features=active_features,
                feature_summary=feature_summary,
                model_info=self.get_model_info(),
                error_message=error_message,
                scan_id=scan_id
            )
            
            db.add(result)
            db.commit()
            db.refresh(result)
            
            self.logger.info(f"Saved AI analysis result with ID: {result.id}")
            return result
            
        except Exception as e:
            self.logger.error(f"Error saving analysis result: {e}")
            db.rollback()
            return None
        finally:
            db.close()

    def get_user_analysis_history(self, user_id: int, limit: int = 50) -> List[Dict[str, Any]]:
        """Get analysis history for a user"""
        db = SessionLocal()
        try:
            results = db.query(AIAnalysisResult)\
                       .filter(AIAnalysisResult.user_id == user_id)\
                       .order_by(AIAnalysisResult.analysis_timestamp.desc())\
                       .limit(limit).all()
            
            history = []
            for result in results:
                history.append({
                    "id": result.id,
                    "apk_name": result.apk_name,
                    "prediction": result.prediction,
                    "confidence": result.confidence,
                    "active_features": result.active_features_count,
                    "timestamp": result.analysis_timestamp.isoformat() if result.analysis_timestamp else None,
                    "file_size": result.file_size,
                    "scan_id": result.scan_id
                })
            
            return history
            
        except Exception as e:
            self.logger.error(f"Error getting analysis history: {e}")
            return []
        finally:
            db.close()

    def get_user_statistics(self, user_id: int) -> Dict[str, Any]:
        """Get analysis statistics for a user"""
        db = SessionLocal()
        try:
            # Get all analyses for user
            results = db.query(AIAnalysisResult)\
                       .filter(AIAnalysisResult.user_id == user_id).all()
            
            if not results:
                return {
                    "total_analyses": 0,
                    "malware_detected": 0,
                    "benign_detected": 0,
                    "analysis_errors": 0,
                    "average_confidence": 0.0,
                    "malware_percentage": 0.0
                }
            
            # Calculate statistics
            total = len(results)
            malware_count = sum(1 for r in results if r.prediction == "malware")
            benign_count = sum(1 for r in results if r.prediction == "benign")
            error_count = sum(1 for r in results if r.prediction == "error")
            
            # Calculate average confidence (excluding errors)
            valid_results = [r for r in results if r.prediction != "error"]
            avg_confidence = sum(r.confidence for r in valid_results) / len(valid_results) if valid_results else 0.0
            
            malware_percentage = (malware_count / total) * 100 if total > 0 else 0.0
            
            return {
                "total_analyses": total,
                "malware_detected": malware_count,
                "benign_detected": benign_count,
                "analysis_errors": error_count,
                "average_confidence": round(avg_confidence, 3),
                "malware_percentage": round(malware_percentage, 1)
            }
            
        except Exception as e:
            self.logger.error(f"Error getting user statistics: {e}")
            return {
                "total_analyses": 0,
                "malware_detected": 0,
                "benign_detected": 0,
                "analysis_errors": 0,
                "average_confidence": 0.0,
                "malware_percentage": 0.0
            }
        finally:
            db.close()

    def get_health_status(self) -> Dict[str, Any]:
        """Get health status of AI service"""
        try:
            if not self.is_available():
                return {
                    "status": "unavailable",
                    "ai_available": False,
                    "predictor_loaded": False,
                    "error": "AI module or predictor not available"
                }
            
            # Test basic functionality
            model_info = self.get_model_info()
            
            return {
                "status": "healthy",
                "ai_available": True,
                "predictor_loaded": True,
                "model_info": model_info
            }
            
        except Exception as e:
            self.logger.error(f"Health check failed: {e}")
            return {
                "status": "unhealthy",
                "ai_available": False,
                "predictor_loaded": False,
                "error": str(e)
            }


# Global service instance
ai_analysis_service = AIAnalysisService()