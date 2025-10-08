"""
AI Malware Detection Service

Provides AI-powered malware detection analysis integrated with Matrisks backend.
Communicates with the AI module via HTTP API (running on port 8001).
"""
import os
import json
import logging
import tempfile
import traceback
import requests
from typing import Dict, Any, Optional, List
from datetime import datetime

from sqlalchemy.orm import Session
from app.database import SessionLocal
from app.models import AIAnalysisResult


class AIAnalysisService:
    """Service for AI-powered malware detection analysis via HTTP API"""
    
    def __init__(self):
        """Initialize AI analysis service"""
        self.logger = logging.getLogger(__name__)
        self.ai_service_url = os.environ.get("AI_SERVICE_URL", "http://localhost:8001")
        self.logger.info(f"AI Malware Detection service configured to use API at {self.ai_service_url}")

    def is_available(self) -> bool:
        """Check if AI service is available and functional"""
        try:
            response = requests.get(f"{self.ai_service_url}/ai_detection/health", timeout=5)
            if response.status_code == 200:
                health_data = response.json()
                return health_data.get("status") == "healthy"
            return False
        except Exception as e:
            self.logger.error(f"AI service health check failed: {e}")
            return False

    def get_model_info(self) -> Dict[str, Any]:
        """Get information about the AI model"""
        try:
            response = requests.get(f"{self.ai_service_url}/ai_detection/info", timeout=5)
            if response.status_code == 200:
                info = response.json()
                return {
                    "available": True,
                    "model_type": info.get("model_type", "RandomForestClassifier"),
                    "feature_count": info.get("feature_count", 215),
                    "model_loaded": info.get("model_loaded", False)
                }
            else:
                return {
                    "available": False,
                    "error": f"AI service returned status {response.status_code}"
                }
        except Exception as e:
            self.logger.error(f"Error getting model info: {e}")
            return {
                "available": False,
                "error": str(e)
            }

    def analyze_apk(self, apk_path: str, user_id: int, apk_name: str, scan_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Analyze APK file using AI malware detection via HTTP API
        
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
            # Verify file exists
            if not os.path.exists(apk_path):
                error_msg = f"APK file not found: {apk_path}"
                self.logger.error(error_msg)
                return {
                    "success": False,
                    "error": error_msg,
                    "prediction": "error"
                }

            # Perform AI analysis via HTTP API
            self.logger.info(f"Starting AI analysis for APK: {apk_name} at {apk_path}")
            
            # Upload APK to AI service
            with open(apk_path, 'rb') as f:
                files = {'file': (apk_name, f, 'application/vnd.android.package-archive')}
                response = requests.post(
                    f"{self.ai_service_url}/ai_detection/upload",
                    files=files,
                    timeout=120  # 2 minutes timeout for analysis
                )
            
            if response.status_code != 200:
                error_msg = f"AI service returned status {response.status_code}: {response.text}"
                self.logger.error(error_msg)
                return {
                    "success": False,
                    "error": error_msg,
                    "prediction": "error"
                }
            
            result = response.json()
            
            # Check if there was an error in the analysis
            if result.get("prediction") == "error":
                error_msg = result.get("error", "Unknown error during analysis")
                self.logger.error(f"AI analysis failed: {error_msg}")
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
            
            # Get file size
            file_size = os.path.getsize(apk_path) if os.path.exists(apk_path) else 0
            
            # Extract feature information from the result structure
            feature_summary = result.get("feature_summary", {})
            active_features_count = feature_summary.get("active_features", 0)
            total_features = feature_summary.get("total_features", 215)
            
            # Prepare analysis result with ALL available information
            analysis_result = {
                "success": True,
                "prediction": result["prediction"],
                "confidence": result["confidence"], 
                "risk_level": self._get_risk_level(result["prediction"], result["confidence"]),
                "active_features": active_features_count,
                "total_features": total_features,
                "feature_analysis": feature_summary,
                "model_info": result.get("model_info", self.get_model_info()),
                "timestamp": result.get("timestamp", datetime.now().isoformat()),
                "file_size": file_size,
                "apk_name": result.get("apk_name", apk_name),
                # Additional detailed information from AI module
                "probabilities": result.get("probabilities", {}),
                "model_prediction": result.get("model_prediction"),
                "model_confidence": result.get("model_confidence"),
                "heuristic_adjustment": result.get("heuristic_adjustment", {}),
                "active_feature_list": feature_summary.get("active_feature_list", [])
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
                # Generate scan_id for file download
                scan_dir_name = f"SCAN-{db_result.analysis_timestamp.strftime('%Y%m%d-%H%M%S')}-{db_result.id}"
                analysis_result["scan_id"] = scan_dir_name
            
            self.logger.info(f"AI analysis completed for {apk_name}: {result['prediction']} ({result['confidence']:.2f})")
            return analysis_result
            
        except requests.exceptions.Timeout:
            error_msg = "AI analysis timed out. The APK file may be too large or complex."
            self.logger.error(error_msg)
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
        except requests.exceptions.ConnectionError:
            error_msg = "Cannot connect to AI service. Please ensure the AI module is running."
            self.logger.error(error_msg)
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
        """Save analysis result to database and create scan directory structure"""
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
            
            # Create scan directory structure similar to static scans
            self._create_scan_directory(result, user_id)
            
            self.logger.info(f"Saved AI analysis result with ID: {result.id}")
            return result
            
        except Exception as e:
            self.logger.error(f"Error saving analysis result: {e}")
            db.rollback()
            return None
        finally:
            db.close()

    def _create_scan_directory(self, result: AIAnalysisResult, user_id: int) -> None:
        """
        Create a scan directory structure for AI analysis to match static scan format
        
        Args:
            result: AI analysis result from database
            user_id: ID of the user who performed the analysis
        """
        try:
            import json
            from pathlib import Path
            
            # Create AI scans directory
            project_root = Path(__file__).parent.parent.parent.parent
            ai_scans_dir = project_root / "ai_based_malware_detection" / "scanned_results"
            ai_scans_dir.mkdir(parents=True, exist_ok=True)
            
            # Create scan directory with timestamp
            scan_dir_name = f"SCAN-{result.analysis_timestamp.strftime('%Y%m%d-%H%M%S')}-{result.id}"
            scan_dir = ai_scans_dir / scan_dir_name
            scan_dir.mkdir(exist_ok=True)
            
            # Create manifest.json matching static scan format
            manifest_data = {
                "scan_id": scan_dir_name,
                "apk_name": result.apk_name,
                "file_size": result.file_size or 0,
                "analysis_type": "AI Malware Detection",
                "user_id": user_id,
                "created_at": result.analysis_timestamp.isoformat() if result.analysis_timestamp else datetime.now().isoformat(),
                "updated_at": datetime.now().isoformat(),
                "prediction": result.prediction,
                "confidence": result.confidence,
                "risk_level": self._get_risk_level(result.prediction, result.confidence),
                "active_features": result.active_features_count,
                "total_features": result.total_features,
                "database_id": result.id
            }
            
            manifest_path = scan_dir / "manifest.json"
            with open(manifest_path, 'w') as f:
                json.dump(manifest_data, f, indent=4)
            
            # Create comprehensive JSON report
            report_data = {
                "report_metadata": {
                    "report_title": "AI Malware Detection Analysis Report",
                    "generated_at": datetime.now().isoformat(),
                    "report_version": "2.0",
                    "analysis_id": result.id,
                    "scan_id": scan_dir_name,
                    "apk_name": result.apk_name
                },
                "executive_summary": {
                    "classification": result.prediction,
                    "confidence_score": result.confidence,
                    "confidence_percentage": f"{(result.confidence * 100):.2f}%",
                    "risk_level": self._get_risk_level(result.prediction, result.confidence),
                    "threat_assessment": self._get_threat_assessment(result.prediction, result.confidence),
                    "recommendation": self._get_recommendation(result.prediction, result.confidence)
                },
                "detection_details": {
                    "model_type": result.model_info.get("model_type", "RandomForestClassifier") if result.model_info else "RandomForestClassifier",
                    "total_features_analyzed": result.total_features,
                    "active_features_detected": result.active_features_count,
                    "feature_activation_rate": f"{((result.active_features_count / result.total_features) * 100):.1f}%" if result.total_features else "0%"
                },
                "file_information": {
                    "file_name": result.apk_name,
                    "file_size_bytes": result.file_size or 0,
                    "file_size_mb": f"{((result.file_size or 0) / (1024 * 1024)):.2f}",
                    "analysis_timestamp": result.analysis_timestamp.isoformat() if result.analysis_timestamp else None
                },
                "full_analysis_data": {
                    "prediction": result.prediction,
                    "confidence": result.confidence,
                    "active_features": result.active_features,
                    "feature_summary": result.feature_summary,
                    "model_info": result.model_info,
                    "error_message": result.error_message
                }
            }
            
            report_path = scan_dir / "report.json"
            with open(report_path, 'w') as f:
                json.dump(report_data, f, indent=2)
            
            self.logger.info(f"Created scan directory structure at: {scan_dir}")
            
        except Exception as e:
            self.logger.error(f"Failed to create scan directory: {e}")
            # Don't raise - this is not critical, database record is the source of truth

    def _get_threat_assessment(self, prediction: str, confidence: float) -> str:
        """Get threat assessment string"""
        if prediction == "malware":
            if confidence > 0.8:
                return "CRITICAL - High confidence malware detection"
            elif confidence > 0.6:
                return "HIGH - Moderate confidence malware detection"
            else:
                return "MEDIUM - Low confidence malware detection"
        else:
            if confidence > 0.8:
                return "SAFE - High confidence benign classification"
            elif confidence > 0.6:
                return "LIKELY SAFE - Moderate confidence benign classification"
            else:
                return "UNCERTAIN - Low confidence benign classification"
    
    def _get_recommendation(self, prediction: str, confidence: float) -> str:
        """Get recommendation string"""
        if prediction == "malware":
            return "DO NOT INSTALL - Quarantine or delete this APK immediately"
        else:
            if confidence < 0.6:
                return "Appears safe, but verify permissions and consider additional scans before installation"
            else:
                return "Appears safe, but verify permissions before installation"

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
            response = requests.get(f"{self.ai_service_url}/ai_detection/health", timeout=5)
            if response.status_code == 200:
                health_data = response.json()
                return {
                    "status": "healthy" if health_data.get("status") == "healthy" else "unhealthy",
                    "ai_available": True,
                    "ai_service_url": self.ai_service_url,
                    "health_data": health_data
                }
            else:
                return {
                    "status": "unhealthy",
                    "ai_available": False,
                    "error": f"AI service returned status {response.status_code}"
                }
        except Exception as e:
            self.logger.error(f"Health check failed: {e}")
            return {
                "status": "unavailable",
                "ai_available": False,
                "error": str(e),
                "ai_service_url": self.ai_service_url
            }

    def get_analysis_history(self, user_id: int, db: Session, limit: int = 50) -> List[Dict[str, Any]]:
        """
        Get analysis history for a user (wrapper for compatibility)
        
        Args:
            user_id: User ID
            db: Database session
            limit: Maximum number of records
            
        Returns:
            List of analysis records
        """
        return self.get_user_analysis_history(user_id, limit)
    
    def get_analysis_statistics(self, user_id: int, db: Session) -> Dict[str, Any]:
        """
        Get analysis statistics for a user (wrapper for compatibility)
        
        Args:
            user_id: User ID
            db: Database session
            
        Returns:
            Statistics dictionary
        """
        return self.get_user_statistics(user_id)
    
    def get_analysis_by_id(self, analysis_id: int, user_id: int, db: Session) -> Optional[Dict[str, Any]]:
        """
        Get a specific analysis result by ID
        
        Args:
            analysis_id: Analysis record ID
            user_id: User ID (for authorization)
            db: Database session
            
        Returns:
            Analysis result or None
        """
        try:
            result = db.query(AIAnalysisResult)\
                      .filter(AIAnalysisResult.id == analysis_id)\
                      .filter(AIAnalysisResult.user_id == user_id)\
                      .first()
            
            if not result:
                return None
            
            return {
                "id": result.id,
                "apk_name": result.apk_name,
                "file_size": result.file_size,
                "prediction": result.prediction,
                "confidence": result.confidence,
                "active_features_count": result.active_features_count,
                "total_features": result.total_features,
                "active_features": result.active_features,
                "feature_summary": result.feature_summary,
                "model_info": result.model_info,
                "timestamp": result.analysis_timestamp.isoformat() if result.analysis_timestamp else None,
                "error_message": result.error_message,
                "scan_id": result.scan_id
            }
        except Exception as e:
            self.logger.error(f"Error getting analysis by ID {analysis_id}: {e}")
            return None


# Global service instance
ai_analysis_service = AIAnalysisService()