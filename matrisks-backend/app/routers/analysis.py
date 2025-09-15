"""
Analysis router for APK security analysis
"""
from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File, Form
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from typing import Dict, Any
import tempfile
import os
from pathlib import Path

from app.database import get_db
from app.schemas import UserOut
from app.routers.auth import get_current_user
from app.services.analysis import AnalysisService

router = APIRouter(
    prefix="/analysis",
    tags=["analysis"],
)

@router.post("/scan")
async def scan_apk(
    file: UploadFile = File(...),
    analysis_type: str = Form("basic"),
    db: Session = Depends(get_db),
    current_user: UserOut = Depends(get_current_user)
) -> Dict[str, Any]:
    """
    Analyze an uploaded APK file for security vulnerabilities
    
    Args:
        file: APK file to analyze
        analysis_type: Type of analysis (basic, advanced, dynamic, malware)
        db: Database session
        current_user: Current authenticated user
        
    Returns:
        Analysis results
    """
    # Validate file type
    if not file.filename.endswith('.apk'):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only APK files are supported"
        )
    
    # Validate analysis type
    valid_types = ["basic", "advanced", "dynamic", "malware"]
    if analysis_type not in valid_types:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid analysis type. Must be one of: {', '.join(valid_types)}"
        )
    
    # Create temporary file for the uploaded APK
    with tempfile.NamedTemporaryFile(delete=False, suffix='.apk') as temp_file:
        try:
            # Write uploaded file to temporary file
            content = await file.read()
            temp_file.write(content)
            temp_file.flush()
            
            # Initialize analysis service
            analysis_service = AnalysisService()
            
            # Perform analysis
            results = analysis_service.analyze_apk(temp_file.name, analysis_type)
            
            if not results.get("success", False):
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=results.get("error", "Analysis failed")
                )
            
            # Add metadata
            results["file_info"] = {
                "filename": file.filename,
                "size": len(content),
                "content_type": file.content_type
            }
            
            return results
            
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Analysis failed: {str(e)}"
            )
        finally:
            # Clean up temporary file
            try:
                os.unlink(temp_file.name)
            except:
                pass

@router.get("/types")
async def get_analysis_types() -> Dict[str, Any]:
    """
    Get available analysis types and their descriptions
    
    Returns:
        Available analysis types
    """
    return {
        "analysis_types": [
            {
                "id": "basic",
                "name": "Basic Analysis",
                "description": "Run basic file scanning & metadata extraction",
                "estimated_time": "1-2 minutes"
            },
            {
                "id": "advanced",
                "name": "Advanced Analysis", 
                "description": "Perform in-depth code analysis & vulnerability scanning",
                "estimated_time": "3-5 minutes"
            },
            {
                "id": "dynamic",
                "name": "Dynamic Analysis",
                "description": "Monitor real-time behavior & detect runtime threats",
                "estimated_time": "5-10 minutes"
            },
            {
                "id": "malware",
                "name": "Malware Detection",
                "description": "Scan for malware using ML-powered detection",
                "estimated_time": "2-3 minutes"
            }
        ]
    }

@router.get("/vectors")
async def get_security_vectors() -> Dict[str, Any]:
    """
    Get available security vectors that are checked during analysis
    
    Returns:
        List of security vectors
    """
    return {
        "security_vectors": [
            {
                "id": "permissions",
                "name": "Permission Analysis",
                "description": "Checks if app has correct permissions",
                "category": "Permissions"
            },
            {
                "id": "ssl",
                "name": "SSL/TLS Security",
                "description": "Checks SSL Implementation and verifies MITM attack vulnerabilities",
                "category": "Network Security"
            },
            {
                "id": "debug",
                "name": "Debug Mode Detection",
                "description": "Checks if debug mode is enabled and debug certificate detection",
                "category": "Development Security"
            },
            {
                "id": "webview",
                "name": "WebView Security",
                "description": "Checks WebView vulnerabilities and JavaScript interface issues",
                "category": "Web Security"
            },
            {
                "id": "storage",
                "name": "Storage Security",
                "description": "App sandbox permission check and external storage access",
                "category": "Data Protection"
            },
            {
                "id": "database",
                "name": "Database Security",
                "description": "SQLite database encryption and vulnerability checks",
                "category": "Data Protection"
            },
            {
                "id": "runtime_exec",
                "name": "Runtime Execution",
                "description": "Checks for dangerous runtime command execution",
                "category": "Code Security"
            },
            {
                "id": "native_methods",
                "name": "Native Methods",
                "description": "Native library loading and method analysis",
                "category": "Code Security"
            },
            {
                "id": "sensitive",
                "name": "Sensitive Data",
                "description": "Checks for access to sensitive device information",
                "category": "Privacy"
            },
            {
                "id": "keystore",
                "name": "Keystore Security",
                "description": "Keystore protection and SSL pinning checks",
                "category": "Cryptography"
            }
        ]
    }

@router.get("/download/{scan_id}")
async def download_report(
    scan_id: str,
    current_user: UserOut = Depends(get_current_user)
):
    """
    Download the HTML report for a specific scan
    
    Args:
        scan_id: The scan ID (directory name in scanned_results)
        current_user: Current authenticated user
        
    Returns:
        HTML report file
    """
    try:
        # Initialize analysis service to get the path
        analysis_service = AnalysisService()
        basicstatic_path = analysis_service.basicstatic_path
        
        # Construct the report path
        report_path = basicstatic_path / "scanned_results" / scan_id / "report.html"
        
        # Check if the report exists
        if not report_path.exists():
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Report not found"
            )
        
        # Return the file
        return FileResponse(
            path=str(report_path),
            filename=f"security_report_{scan_id}.html",
            media_type="text/html"
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to download report: {str(e)}"
        )
