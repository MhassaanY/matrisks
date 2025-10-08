from fastapi import APIRouter, Depends, HTTPException, status, Response
from sqlalchemy.orm import Session
from typing import List, Dict, Any
import os
import json
from pathlib import Path
from datetime import datetime

from app.database import get_db
from app.schemas import UserOut
from app.crud import user as user_crud
from app.routers.auth import get_current_user

router = APIRouter(
    prefix="/admin",
    tags=["admin"],
)

@router.get("/users", response_model=List[UserOut])
async def get_all_users(
    db: Session = Depends(get_db),
    current_user: UserOut = Depends(get_current_user)
):
    """
    Get all users (admin only)
    
    Args:
        db: Database session
        current_user: Current authenticated user
        
    Returns:
        List of all users
        
    Raises:
        HTTPException: If user is not an admin
    """
    if not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only superusers can access this resource"
        )
    
    users = user_crud.get_all_users(db)
    return users

@router.delete("/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: UserOut = Depends(get_current_user)
):
    """
    Delete a user by ID (admin only)
    
    Args:
        user_id: ID of the user to delete
        db: Database session
        current_user: Current authenticated user
        
    Raises:
        HTTPException: If user is not an admin or user not found
    """
    if not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only superusers can delete users"
        )
    
    user = user_crud.get_by_id(db, user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    user_crud.delete_user(db, user_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)

@router.get("/engines")
async def get_analysis_engines(
    current_user: UserOut = Depends(get_current_user)
):
    """
    Get all available analysis engines (admin only)
    
    Args:
        current_user: Current authenticated user
        
    Returns:
        List of analysis engines with their metadata
        
    Raises:
        HTTPException: If user is not an admin
    """
    if not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only superusers can access this resource"
        )
    
    # Get the project root directory
    project_root = Path(__file__).parent.parent.parent.parent
    
    engines = []
    
    # Check for Basic Static Analysis Engine
    basic_static_path = project_root / "matrisksBasicStatic"
    if basic_static_path.exists():
        engines.append({
            "id": "basic-static",
            "name": "Basic Static Analysis",
            "description": "Basic APK analysis with metadata extraction and security scanning",
            "status": "active",
            "version": "1.0.0",
            "path": str(basic_static_path),
            "supported_formats": ["html", "pdf"],
            "last_updated": datetime.fromtimestamp(basic_static_path.stat().st_mtime).isoformat()
        })
    
    # Check for Advanced Static Analysis Engine
    advanced_static_path = project_root / "matrisksAdvanceStatic"
    if advanced_static_path.exists():
        engines.append({
            "id": "advanced-static",
            "name": "Advanced Static Analysis",
            "description": "Advanced APK analysis with comprehensive vulnerability scanning and detailed reporting",
            "status": "active",
            "version": "2.0.0",
            "path": str(advanced_static_path),
            "supported_formats": ["html", "json", "csv", "pdf"],
            "last_updated": datetime.fromtimestamp(advanced_static_path.stat().st_mtime).isoformat()
        })
    
    return engines

@router.get("/analysis-history")
async def get_analysis_history(
    current_user: UserOut = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get analysis history with metadata (admin only, includes both static and AI analyses)
    
    Args:
        current_user: Current authenticated user
        db: Database session
        
    Returns:
        List of analysis records with metadata
        
    Raises:
        HTTPException: If user is not an admin
    """
    if not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only superusers can access this resource"
        )
    
    # Get the project root directory
    project_root = Path(__file__).parent.parent.parent.parent
    
    analysis_history = []
    
    # 1. Scan both basic, advanced static, and AI directories for analysis results
    for engine_name, engine_path in [
        ("Basic Static", project_root / "matrisksBasicStatic"),
        ("Advanced Static", project_root / "matrisksAdvanceStatic"),
        ("AI Malware Detection", project_root / "ai_based_malware_detection")
    ]:
        results_dir = engine_path / "scanned_results"
        if results_dir.exists():
            for scan_dir in results_dir.iterdir():
                if scan_dir.is_dir() and scan_dir.name.startswith("SCAN-"):
                    # Read manifest.json if it exists
                    manifest_path = scan_dir / "manifest.json"
                    manifest_data = {}
                    if manifest_path.exists():
                        try:
                            with open(manifest_path, 'r') as f:
                                manifest_data = json.load(f)
                        except Exception as e:
                            print(f"Failed to read manifest for {scan_dir.name}: {e}")
                            continue
                    
                    # Get file info from manifest
                    apk_name = manifest_data.get("apk_name", "Unknown APK")
                    file_size = manifest_data.get("file_size", 0)
                    
                    # Check what report formats are available
                    available_formats = []
                    for format_ext in ["html", "json", "csv", "pdf"]:
                        if (scan_dir / f"report.{format_ext}").exists():
                            available_formats.append(format_ext)
                    
                    # Build entry data
                    entry = {
                        "id": scan_dir.name,
                        "apk_name": apk_name,
                        "file_size": file_size,
                        "analysis_type": engine_name,
                        "timestamp": manifest_data.get("created_at", 
                            datetime.fromtimestamp(scan_dir.stat().st_mtime).isoformat()),
                        "status": "completed",
                        "available_formats": available_formats,
                        "scan_path": str(scan_dir),
                        "user": f"User {manifest_data.get('user_id', 'Unknown')}",
                        "engine_path": str(engine_path)
                    }
                    
                    # Add AI-specific fields if this is an AI scan
                    if engine_name == "AI Malware Detection":
                        entry["prediction"] = manifest_data.get("prediction", "unknown")
                        entry["confidence"] = manifest_data.get("confidence", 0.0)
                    
                    analysis_history.append(entry)
    
    # 2. Also get AI malware detection results from database (for backward compatibility)
    # This catches any AI scans that might not have scan directories yet
    try:
        from app.models import AIAnalysisResult
        ai_results = db.query(AIAnalysisResult)\
                       .order_by(AIAnalysisResult.analysis_timestamp.desc())\
                       .limit(100).all()
        
        # Get existing scan IDs to avoid duplicates
        existing_scan_ids = {entry["id"] for entry in analysis_history}
        
        # Add AI results that don't already have a scan directory
        for ai_record in ai_results:
            scan_id = f"SCAN-{ai_record.analysis_timestamp.strftime('%Y%m%d-%H%M%S')}-{ai_record.id}" if ai_record.analysis_timestamp else f"SCAN-{ai_record.id}"
            
            # Only add if not already in the list
            if scan_id not in existing_scan_ids:
                analysis_history.append({
                    "id": scan_id,
                    "apk_name": ai_record.apk_name,
                    "file_size": ai_record.file_size or 0,
                    "analysis_type": "AI Malware Detection",
                    "timestamp": ai_record.analysis_timestamp.isoformat() if ai_record.analysis_timestamp else datetime.now().isoformat(),
                    "status": "completed" if ai_record.prediction != 'error' else 'error',
                    "available_formats": ["json"],  # Database records have JSON data
                    "scan_path": "",
                    "user": f"User {ai_record.user_id}",
                    "engine_path": "",
                    "prediction": ai_record.prediction,
                    "confidence": ai_record.confidence
                })
    except Exception as e:
        print(f"Error loading AI analysis history: {e}")
    
    # Sort by timestamp (newest first)
    analysis_history.sort(key=lambda x: x["timestamp"], reverse=True)
    
    return analysis_history
