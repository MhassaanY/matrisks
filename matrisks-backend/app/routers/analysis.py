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
from datetime import datetime

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
            results = analysis_service.analyze_apk(temp_file.name, analysis_type, current_user.id, file.filename)
            
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
    format: str = "html",
    current_user: UserOut = Depends(get_current_user)
):
    """
    Download a report for a specific scan in the requested format
    
    Args:
        scan_id: The scan ID (directory name in scanned_results)
        format: Report format (html, json, csv, pdf)
        current_user: Current authenticated user
        
    Returns:
        Report file in the requested format
    """
    try:
        # Initialize analysis service to get the paths
        analysis_service = AnalysisService()
        basicstatic_path = analysis_service.basicstatic_path
        advancestatic_path = analysis_service.advancestatic_path
        
        # Map format to file extension and media type
        format_map = {
            "html": ("report.html", "text/html", "html"),
            "json": ("report.json", "application/json", "json"),
            "csv": ("report.csv", "text/csv", "csv"),
            "pdf": ("report.pdf", "application/pdf", "pdf")
        }
        
        if format not in format_map:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid format. Must be one of: html, json, csv, pdf"
            )
        
        filename, media_type, file_ext = format_map[format]
        
        # Try to find the report in both basic and advanced static directories
        report_path = None
        for base_path in [basicstatic_path, advancestatic_path]:
            potential_path = base_path / "scanned_results" / scan_id / filename
            if potential_path.exists():
                report_path = potential_path
                break
        
        # Check if the report exists
        if not report_path:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Report not found for format: {format}"
            )
        
        # Return the file
        return FileResponse(
            path=str(report_path),
            filename=f"security_report_{scan_id}.{file_ext}",
            media_type=media_type
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to download report: {str(e)}"
        )

@router.get("/history")
async def get_user_analysis_history(
    current_user: UserOut = Depends(get_current_user)
) -> Dict[str, Any]:
    """
    Get analysis history for the current user
    
    Args:
        current_user: Current authenticated user
        
    Returns:
        List of analysis records for the current user
    """
    try:
        # Get the project root directory
        project_root = Path(__file__).parent.parent.parent.parent
        
        analysis_history = []
        
        # Scan both basic and advanced static directories for analysis results
        for engine_name, engine_path in [
            ("Basic Static", project_root / "matrisksBasicStatic"),
            ("Advanced Static", project_root / "matrisksAdvanceStatic")
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
                                import json
                                with open(manifest_path, 'r') as f:
                                    manifest_data = json.load(f)
                            except:
                                pass
                        
                        # Check if this scan belongs to the current user
                        user_id = manifest_data.get("user_id")
                        if user_id is None:
                            # Skip scans without user tracking (older scans)
                            continue
                        if str(user_id) != str(current_user.id):
                            # Skip scans not belonging to current user
                            continue
                        
                        # Get file info
                        apk_name = manifest_data.get("apk_name", "Unknown APK")
                        file_size = manifest_data.get("file_size", 0)
                        
                        # Check what report formats are available
                        available_formats = []
                        for format_ext in ["html", "json", "csv", "pdf"]:
                            if (scan_dir / f"report.{format_ext}").exists():
                                available_formats.append(format_ext)
                        
                        analysis_history.append({
                            "id": scan_dir.name,
                            "apk_name": apk_name,
                            "file_size": file_size,
                            "analysis_type": engine_name,
                            "timestamp": manifest_data.get("created_at", 
                                datetime.fromtimestamp(scan_dir.stat().st_mtime).isoformat()),
                            "status": "completed",
                            "available_formats": available_formats,
                            "scan_path": str(scan_dir),
                            "user_id": user_id
                        })
        
        # Sort by timestamp (newest first)
        analysis_history.sort(key=lambda x: x["timestamp"], reverse=True)
        
        return {
            "success": True,
            "data": analysis_history,
            "total": len(analysis_history)
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to fetch analysis history: {str(e)}"
        )
