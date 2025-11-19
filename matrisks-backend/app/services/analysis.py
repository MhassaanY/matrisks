"""
Analysis service for integrating BasicStatic engine with FastAPI
"""
import os
import json
import subprocess
import tempfile
import shutil
import uuid
import time
from pathlib import Path
from typing import Dict, Any, Optional
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

class AnalysisService:
    def __init__(self):
        # Paths to analysis engines
        repo_root = Path(__file__).parent.parent.parent.parent
        self.basicstatic_path = repo_root / "matrisksBasicStatic"
        self.advancestatic_path = repo_root / "matrisksAdvanceStatic"
        self.dynamic_path = repo_root / "matrisksDynamicAnalyzer"

        # These are set per-run based on analysis_type
        self._engine_path: Optional[Path] = None
        self._python_path: Optional[Path] = None
        self._matrisks_script: Optional[Path] = None
        
    def _extract_apk_metadata(self, apk_file_path: str, original_filename: str = None) -> Dict[str, Any]:
        """
        Extract basic metadata from APK file
        
        Args:
            apk_file_path: Path to the APK file
            original_filename: Original filename of the uploaded APK
            
        Returns:
            Dictionary containing APK metadata
        """
        try:
            import os
            from pathlib import Path
            
            apk_path = Path(apk_file_path)
            file_size = apk_path.stat().st_size
            
            # Use original filename if provided, otherwise fall back to temp file name
            apk_name = original_filename if original_filename else apk_path.name
            
            return {
                "apk_name": apk_name,
                "file_size": file_size,
                "file_path": str(apk_path),
                "upload_timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            logger.warning(f"Failed to extract APK metadata: {e}")
            return {
                "apk_name": original_filename if original_filename else "Unknown APK",
                "file_size": 0,
                "file_path": apk_file_path,
                "upload_timestamp": datetime.now().isoformat()
            }
    
    def _update_manifest_with_metadata(self, apk_metadata: Dict[str, Any], user_id: int = None) -> None:
        """
        Update the manifest.json file with APK metadata and user information
        
        Args:
            apk_metadata: Dictionary containing APK metadata
            user_id: ID of the user who performed the analysis
        """
        try:
            latest_scan = self._get_latest_scan_directory()
            if not latest_scan:
                logger.warning("No scan directory found to update manifest")
                return
            
            manifest_path = latest_scan / "manifest.json"
            
            # Read existing manifest or create new one
            manifest_data = {}
            if manifest_path.exists():
                try:
                    with open(manifest_path, 'r') as f:
                        manifest_data = json.load(f)
                except Exception as e:
                    logger.warning(f"Failed to read existing manifest: {e}")
                    manifest_data = {}
            
            # Update with APK metadata and user information
            manifest_data.update({
                "apk_name": apk_metadata.get("apk_name", "Unknown APK"),
                "file_size": apk_metadata.get("file_size", 0),
                "file_path": apk_metadata.get("file_path", ""),
                "upload_timestamp": apk_metadata.get("upload_timestamp", ""),
                "user_id": user_id,
                "updated_at": datetime.now().isoformat()
            })
            
            # Write updated manifest
            with open(manifest_path, 'w') as f:
                json.dump(manifest_data, f, indent=4)
            
            logger.info(f"Updated manifest.json with APK metadata: {apk_metadata.get('apk_name')}")
            
        except Exception as e:
            logger.error(f"Failed to update manifest with metadata: {e}")
        
    def analyze_apk(self, apk_file_path: str, analysis_type: str = "basic", user_id: int = None, original_filename: str = None) -> Dict[str, Any]:
        """
        Analyze an APK file using BasicStatic engine, Dynamic Analyzer, or AI malware detection
        
        Args:
            apk_file_path: Path to the APK file
            analysis_type: Type of analysis (basic, advanced, dynamic, malware)
            user_id: ID of the user performing analysis
            original_filename: Original filename of the uploaded APK
            
        Returns:
            Dictionary containing analysis results
        """
        # Handle AI malware detection separately
        if analysis_type == "malware":
            return self._analyze_with_ai(apk_file_path, user_id, original_filename)
        
        # Handle Dynamic Analysis separately
        if analysis_type == "dynamic":
            return self._analyze_with_dynamic(apk_file_path, user_id, original_filename)
            
        try:
            # Extract APK metadata before analysis
            apk_metadata = self._extract_apk_metadata(apk_file_path, original_filename)
            
            # Create temporary directory for analysis
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_apk_path = os.path.join(temp_dir, "uploaded.apk")
                
                # Copy APK to temp directory
                shutil.copy2(apk_file_path, temp_apk_path)
                
                # Select engine based on analysis_type
                if analysis_type == "advanced":
                    engine_path = self.advancestatic_path
                else:
                    engine_path = self.basicstatic_path

                self._engine_path = engine_path
                # Use the backend venv which has all required dependencies
                self._python_path = self.basicstatic_path.parent / "matrisks-backend" / "venv" / "bin" / "python3"
                self._matrisks_script = engine_path / "matrisks.py"

                # Build command
                cmd = [str(self._python_path), str(self._matrisks_script), "-f", temp_apk_path]
                
                logger.info(f"Running analysis command: {' '.join(cmd)}")
                
                # Execute the analysis
                result = subprocess.run(
                    cmd,
                    cwd=str(engine_path),
                    capture_output=True,
                    text=True,
                    timeout=300  # 5 minute timeout
                )
                
                if result.returncode != 0:
                    logger.error(f"Analysis failed with return code {result.returncode}")
                    logger.error(f"Error output: {result.stderr}")
                    return {
                        "success": False,
                        "error": f"Analysis failed: {result.stderr}",
                        "return_code": result.returncode
                    }
                
                # Parse the output to extract key information
                analysis_results = self._parse_analysis_output(result.stdout)
                
                # Try to find the generated report files
                report_data = self._extract_report_data()
                
                # Update manifest.json with APK metadata and user info
                self._update_manifest_with_metadata(apk_metadata, user_id)
                
                # Get the actual scan directory name as analysis ID
                latest_scan_dir = self._get_latest_scan_directory()
                analysis_id = latest_scan_dir.name if latest_scan_dir else str(uuid.uuid4())
                
                return {
                    "success": True,
                    "analysis_id": analysis_id,
                    "analysis_type": analysis_type,
                    "timestamp": datetime.now().isoformat(),
                    "file_info": {
                        "filename": apk_metadata.get("apk_name", "Unknown APK"),
                        "size": apk_metadata.get("file_size", 0),
                        "upload_timestamp": apk_metadata.get("upload_timestamp")
                    },
                    "results": analysis_results,
                    "report": report_data,
                    "report_content": self._get_report_content(report_data),
                    "report_path": str(self._get_latest_scan_directory()) if self._get_latest_scan_directory() else None,
                    "raw_output": result.stdout
                }
                
        except subprocess.TimeoutExpired:
            logger.error("Analysis timed out after 5 minutes")
            return {
                "success": False,
                "error": "Analysis timed out. The APK might be too large or complex."
            }
        except Exception as e:
            logger.error(f"Analysis failed with exception: {str(e)}")
            return {
                "success": False,
                "error": f"Analysis failed: {str(e)}"
            }
    
    def _parse_analysis_output(self, output: str) -> Dict[str, Any]:
        """
        Parse the BasicStatic analysis output to extract key information
        """
        results = {
            "package_info": {},
            "security_issues": [],
            "summary": {
                "total_issues": 0,
                "critical_issues": 0,
                "warning_issues": 0,
                "info_issues": 0
            }
        }
        
        lines = output.split('\n')
        current_section = None
        
        for line in lines:
            line = line.strip()
            
            # Extract package information
            if line.startswith("Package Name:"):
                results["package_info"]["name"] = line.split(":", 1)[1].strip()
            elif line.startswith("Package Version Name:"):
                results["package_info"]["version_name"] = line.split(":", 1)[1].strip()
            elif line.startswith("Package Version Code:"):
                results["package_info"]["version_code"] = line.split(":", 1)[1].strip()
            elif line.startswith("Min Sdk:"):
                results["package_info"]["min_sdk"] = line.split(":", 1)[1].strip()
            elif line.startswith("Target Sdk:"):
                results["package_info"]["target_sdk"] = line.split(":", 1)[1].strip()
            elif line.startswith("MD5"):
                results["package_info"]["md5"] = line.split(":", 1)[1].strip()
            elif line.startswith("SHA256"):
                results["package_info"]["sha256"] = line.split(":", 1)[1].strip()
            
            # Extract security issues
            elif line.startswith("[Critical]"):
                issue = self._parse_security_issue(line, "Critical")
                if issue:
                    results["security_issues"].append(issue)
                    results["summary"]["critical_issues"] += 1
                    results["summary"]["total_issues"] += 1
            elif line.startswith("[Warning]"):
                issue = self._parse_security_issue(line, "Warning")
                if issue:
                    results["security_issues"].append(issue)
                    results["summary"]["warning_issues"] += 1
                    results["summary"]["total_issues"] += 1
            elif line.startswith("[Notice]"):
                issue = self._parse_security_issue(line, "Notice")
                if issue:
                    results["security_issues"].append(issue)
                    results["summary"]["warning_issues"] += 1
                    results["summary"]["total_issues"] += 1
            elif line.startswith("[Info]"):
                issue = self._parse_security_issue(line, "Info")
                if issue:
                    results["security_issues"].append(issue)
                    results["summary"]["info_issues"] += 1
        
        return results
    
    def _parse_security_issue(self, line: str, severity: str) -> Optional[Dict[str, Any]]:
        """
        Parse a security issue line from the analysis output
        """
        try:
            # Extract the issue type and description
            parts = line.split(":", 2)
            if len(parts) >= 3:
                issue_type = parts[1].strip()
                description = parts[2].strip()
                
                return {
                    "severity": severity,
                    "type": issue_type,
                    "description": description,
                    "category": self._categorize_issue(issue_type)
                }
        except Exception as e:
            logger.warning(f"Failed to parse security issue line: {line}, error: {e}")
        
        return None
    
    def _categorize_issue(self, issue_type: str) -> str:
        """
        Categorize security issues based on their type
        """
        issue_type_lower = issue_type.lower()
        
        if "debug" in issue_type_lower:
            return "Debug & Development"
        elif "permission" in issue_type_lower:
            return "Permissions"
        elif "ssl" in issue_type_lower or "certificate" in issue_type_lower:
            return "SSL/TLS Security"
        elif "backup" in issue_type_lower:
            return "Data Protection"
        elif "webview" in issue_type_lower:
            return "WebView Security"
        elif "database" in issue_type_lower or "sqlite" in issue_type_lower:
            return "Database Security"
        elif "storage" in issue_type_lower:
            return "Storage Security"
        else:
            return "General Security"
    
    def _get_latest_scan_directory(self) -> Optional[Path]:
        """
        Get the path to the latest scan directory
        """
        try:
            base_path = self._engine_path or self.basicstatic_path
            results_dir = base_path / "scanned_results"
            if not results_dir.exists():
                return None
            
            # Find the most recent scan directory
            scan_dirs = [d for d in results_dir.iterdir() if d.is_dir() and d.name.startswith("SCAN-")]
            if not scan_dirs:
                return None
            
            return max(scan_dirs, key=lambda x: x.stat().st_mtime)
        except Exception as e:
            logger.warning(f"Failed to get latest scan directory: {e}")
            return None

    def _extract_report_data(self) -> Dict[str, Any]:
        """
        Try to extract report data from the latest scan results
        """
        try:
            # Look for the most recent scan directory
            latest_scan = self._get_latest_scan_directory()
            if not latest_scan:
                return {}
            
            # Read manifest.json if it exists
            manifest_path = latest_scan / "manifest.json"
            manifest_data = {}
            if manifest_path.exists():
                with open(manifest_path, 'r') as f:
                    manifest_data = json.load(f)
            
            return {
                "scan_id": latest_scan.name,
                "manifest": manifest_data,
                "report_files": {
                    "text": str(latest_scan / "report-raw.txt"),
                    "html": str(latest_scan / "report.html"),
                    "json": str(latest_scan / "report.json"),
                    "csv": str(latest_scan / "report.csv"),
                    "pdf": str(latest_scan / "report.pdf")
                }
            }
        except Exception as e:
            logger.warning(f"Failed to extract report data: {e}")
            return {}
    
    def _get_report_content(self, report_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Get the content of generated report files (HTML, JSON, CSV)
        """
        try:
            content = {}
            
            if not report_data or not report_data.get("report_files"):
                return content
            
            report_files = report_data["report_files"]
            
            # Read HTML report
            html_report_path = report_files.get("html")
            if html_report_path and os.path.exists(html_report_path):
                with open(html_report_path, 'r', encoding='utf-8', errors='ignore') as f:
                    html_content = f.read()
                    
                    # Extract body content, styles, and scripts from the HTML
                    import re
                    
                    # Extract CSS styles from <style> tags
                    style_match = re.search(r'<style>(.*?)</style>', html_content, re.DOTALL)
                    styles = style_match.group(1) if style_match else ""
                    
                    # Extract JavaScript from <script> tags
                    script_match = re.search(r'<script>(.*?)</script>', html_content, re.DOTALL)
                    scripts = script_match.group(1) if script_match else ""
                    
                    # Extract body content
                    body_match = re.search(r'<body[^>]*>(.*?)</body>', html_content, re.DOTALL)
                    body_content = body_match.group(1) if body_match else html_content
                    
                    # Create a complete HTML document with Chart.js and all functionality
                    clean_html = f"""
                    <!DOCTYPE html>
                    <html lang="en">
                    <head>
                        <meta charset="UTF-8">
                        <meta name="viewport" content="width=device-width, initial-scale=1.0">
                        <title>Matrisks Security Report</title>
                        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
                        <style>
                            {styles}
                            body {{
                                margin: 0;
                                padding: 0;
                                background-color: #f0f2f5;
                                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
                            }}
                            .container {{
                                max-width: none;
                                margin: 0;
                                padding: 20px;
                            }}
                            .card {{
                                margin-bottom: 20px;
                            }}
                        </style>
                    </head>
                    <body>
                        {body_content}
                        <script>
                            // Wait for DOM to be ready
                            document.addEventListener('DOMContentLoaded', function() {{
                                {scripts}
                            }});
                        </script>
                    </body>
                    </html>
                    """
                    
                    content["html_report"] = clean_html
            
            # Read JSON report
            json_report_path = report_files.get("json")
            if json_report_path and os.path.exists(json_report_path):
                with open(json_report_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content["json_report"] = f.read()
            
            # Read CSV report
            csv_report_path = report_files.get("csv")
            if csv_report_path and os.path.exists(csv_report_path):
                with open(csv_report_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content["csv_report"] = f.read()
                    
            return content
            
        except Exception as e:
            logger.warning(f"Failed to get report content: {e}")
            return {}
    
    def _analyze_with_ai(self, apk_file_path: str, user_id: int = None, original_filename: str = None) -> Dict[str, Any]:
        """
        Analyze APK using AI malware detection
        
        Args:
            apk_file_path: Path to the APK file
            user_id: ID of the user performing analysis
            original_filename: Original filename of the uploaded APK
            
        Returns:
            Dictionary containing AI analysis results
        """
        try:
            from app.services.ai_analysis import ai_analysis_service
            
            logger.info(f"Starting AI malware analysis for user {user_id}: {original_filename}")
            
            # Perform AI analysis
            ai_result = ai_analysis_service.analyze_apk(apk_file_path, user_id, original_filename)
            
            # Format result to match expected structure
            if ai_result.get("success", False):
                # Use scan_id from AI result if available, otherwise generate UUID
                analysis_id = ai_result.get("scan_id", str(uuid.uuid4()))
                
                return {
                    "success": True,
                    "analysis_id": analysis_id,
                    "analysis_type": "malware",
                    "timestamp": ai_result.get("timestamp", datetime.now().isoformat()),
                    "file_info": {
                        "filename": original_filename or "Unknown APK",
                        "size": ai_result.get("file_size", 0)
                    },
                    "results": {
                        "prediction": ai_result.get("prediction", "unknown"),
                        "confidence": ai_result.get("confidence", 0.0),
                        "risk_level": ai_result.get("risk_level", "unknown"),
                        "active_features": ai_result.get("active_features", 0),
                        "total_features": ai_result.get("total_features", 215),
                        "feature_analysis": ai_result.get("feature_analysis", {}),
                        "model_info": ai_result.get("model_info", {}),
                        "analysis_id": ai_result.get("analysis_id"),  # Database ID
                        "scan_id": analysis_id  # File system scan ID
                    },
                    "report": {
                        "ai_analysis": ai_result,
                        "summary": f"AI Malware Detection: {ai_result.get('prediction', 'unknown').title()} (Confidence: {ai_result.get('confidence', 0):.1%})"
                    },
                    "report_content": {
                        "ai_report": self._format_ai_report(ai_result)
                    },
                    "report_path": analysis_id  # Use scan_id as report_path for downloads
                }
            else:
                return {
                    "success": False,
                    "analysis_type": "malware",
                    "error": ai_result.get("error", "AI analysis failed"),
                    "timestamp": ai_result.get("timestamp", datetime.now().isoformat())
                }
                
        except Exception as e:
            logger.error(f"AI malware analysis failed: {e}")
            return {
                "success": False,
                "analysis_type": "malware",
                "error": f"AI analysis failed: {str(e)}",
                "timestamp": datetime.now().isoformat()
            }
    
    def _get_risk_level(self, prediction: str, confidence: float) -> str:
        """Determine risk level based on AI prediction and confidence."""
        if prediction == "error":
            return "unknown"
        elif prediction == "malware":
            if confidence >= 0.8:
                return "high"
            elif confidence >= 0.6:
                return "medium"
            else:
                return "low-medium"
        else:  # benign
            return "low"
    
    def _format_ai_report(self, ai_result: Dict[str, Any]) -> str:
        """Format AI analysis result as a human-readable report."""
        prediction = ai_result.get("prediction", "unknown").title()
        confidence = ai_result.get("confidence", 0.0)
        feature_summary = ai_result.get("feature_summary", {})
        
        report = f"""
AI Malware Detection Report
==========================

APK File: {ai_result.get('apk_name', 'Unknown')}
Analysis Time: {ai_result.get('timestamp', 'Unknown')}

PREDICTION RESULTS:
- Classification: {prediction}
- Confidence Score: {confidence:.1%}
- Risk Level: {self._get_risk_level(ai_result.get('prediction', 'unknown'), confidence).title()}

FEATURE ANALYSIS:
- Total Features Analyzed: {feature_summary.get('total_features', 215)}
- Active Features Detected: {feature_summary.get('active_features', 0)}
- Detection Rate: {(feature_summary.get('active_features', 0) / feature_summary.get('total_features', 215) * 100):.1f}%

ACTIVE FEATURES:
"""
        
        active_features = feature_summary.get("active_feature_list", [])
        if active_features:
            for i, feature in enumerate(active_features[:20], 1):  # Show top 20
                report += f"  {i}. {feature}\n"
            
            if len(active_features) > 20:
                report += f"  ... and {len(active_features) - 20} more features\n"
        else:
            report += "  No suspicious features detected\n"
        
        model_info = ai_result.get("model_info", {})
        if model_info:
            report += f"""
MODEL INFORMATION:
- Model Type: {model_info.get('model_type', 'Unknown')}
- Feature Count: {model_info.get('feature_count', 'Unknown')}
"""
        
        return report
    
    def _analyze_with_dynamic(self, apk_file_path: str, user_id: int = None, original_filename: str = None) -> Dict[str, Any]:
        """
        Analyze APK using Dynamic Analyzer (Frida-based runtime analysis)
        
        Args:
            apk_file_path: Path to the APK file
            user_id: ID of the user performing analysis
            original_filename: Original filename of the uploaded APK
            
        Returns:
            Dictionary containing dynamic analysis results
        """
        analysis_dir = None
        cleanup_performed = False
        
        try:
            logger.info(f"Starting Dynamic Analysis for user {user_id}: {original_filename}")
            
            # CRITICAL: Force cleanup of any lingering emulators from previous failed analyses
            logger.info("Pre-flight check: Cleaning up any stale emulator processes...")
            self._force_cleanup_emulators()
            
            # Extract APK metadata
            apk_metadata = self._extract_apk_metadata(apk_file_path, original_filename)
            
            # Path to Dynamic Analyzer
            dynamic_analyzer_dir = self.dynamic_path
            cli_script = dynamic_analyzer_dir / "cli.py"
            
            # Use backend venv which has all dependencies including Frida
            python_path = self.basicstatic_path.parent / "matrisks-backend" / "venv" / "bin" / "python3"
            
            if not cli_script.exists():
                logger.error(f"Dynamic Analyzer CLI not found at {cli_script}")
                return {
                    "success": False,
                    "error": "Dynamic Analyzer not properly configured",
                    "timestamp": datetime.now().isoformat()
                }
            
            # Build command: python cli.py analyze <apk> --duration 60
            cmd = [
                str(python_path),
                str(cli_script),
                "analyze",
                apk_file_path,
                "--duration", "60"  # 60 seconds analysis duration
            ]
            
            logger.info(f"Running Dynamic Analysis command: {' '.join(cmd)}")
            
            # Execute the analysis (this will take ~3-4 minutes)
            logger.info("Executing Dynamic Analyzer CLI (timeout: 10 minutes)...")
            start_time = datetime.now()
            
            result = subprocess.run(
                cmd,
                cwd=str(dynamic_analyzer_dir),
                capture_output=True,
                text=True,
                timeout=600  # 10 minute timeout (emulator boot + analysis + report)
            )
            
            execution_time = (datetime.now() - start_time).total_seconds()
            logger.info(f"CLI execution completed in {execution_time:.1f} seconds with return code {result.returncode}")
            
            if result.returncode != 0:
                logger.error(f"Dynamic Analysis failed with return code {result.returncode}")
                logger.error(f"Error output: {result.stderr}")
                
                # Parse error message for better user feedback
                error_msg = result.stderr
                user_friendly_error = "Dynamic Analysis failed"
                
                # Check for common issues with detailed detection
                if "more than one emulator" in error_msg.lower():
                    user_friendly_error = (
                        "Multiple emulators detected. Previous analysis may not have cleaned up properly.\n\n"
                        "💡 This has been automatically fixed. Please try again.\n\n"
                        "If the issue persists, contact support."
                    )
                    # Force cleanup was already done, this shouldn't happen
                    self._force_cleanup_emulators()
                elif "Failed to spawn and attach" in error_msg or ("Process com." in error_msg and "not found" in error_msg):
                    user_friendly_error = (
                        "App failed to start in emulator. This usually happens when:\n\n"
                        "• The app is a game or requires native ARM libraries (Unity, Unreal Engine)\n"
                        "• The app crashes on startup in the emulator environment\n"
                        "• The app has anti-emulator or anti-debugging protections\n\n"
                        "💡 Suggestions:\n"
                        "• Try 'Basic Static Analysis' or 'Advanced Static Analysis' instead\n"
                        "• These analysis types work on ALL APKs without requiring the app to run\n"
                        "• Static analysis can still detect most security issues"
                    )
                elif "emulator" in error_msg.lower() and ("not found" in error_msg.lower() or "failed to start" in error_msg.lower()):
                    user_friendly_error = "Android emulator not found or failed to start. Please ensure Android SDK is properly configured."
                elif "timeout" in error_msg.lower() or "timed out" in error_msg.lower():
                    user_friendly_error = "Analysis timed out. The app may be too complex, emulator is too slow, or APK is incompatible."
                elif "frida" in error_msg.lower():
                    user_friendly_error = "Frida instrumentation failed. The app may have anti-debugging protections."
                
                # Ensure cleanup even on CLI failure
                if not cleanup_performed:
                    logger.info("Performing emergency cleanup after CLI failure...")
                    self._emergency_cleanup_dynamic()
                    cleanup_performed = True
                
                return {
                    "success": False,
                    "error": user_friendly_error,
                    "technical_details": error_msg[:500],
                    "return_code": result.returncode,
                    "timestamp": datetime.now().isoformat()
                }
            
            # Find the latest analysis directory
            latest_analysis = self._get_latest_dynamic_analysis_directory()
            analysis_dir = latest_analysis  # Track for cleanup
            
            if not latest_analysis:
                logger.error("Dynamic Analysis completed but no results directory found")
                return {
                    "success": False,
                    "error": "Analysis completed but results not found",
                    "timestamp": datetime.now().isoformat()
                }
            
            analysis_id = latest_analysis.name
            logger.info(f"Dynamic Analysis completed successfully: {analysis_id}")
            
            # Create/update manifest.json with user info
            self._update_dynamic_manifest(latest_analysis, apk_metadata, user_id)
            
            # Load the comprehensive report
            report_data = self._load_dynamic_report(latest_analysis)
            
            # Parse analysis results
            analysis_summary = self._parse_dynamic_results(report_data)
            
            return {
                "success": True,
                "analysis_id": analysis_id,
                "analysis_type": "dynamic",
                "timestamp": datetime.now().isoformat(),
                "file_info": {
                    "filename": apk_metadata.get("apk_name", "Unknown APK"),
                    "size": apk_metadata.get("file_size", 0)
                },
                "results": analysis_summary,
                "report": {
                    "scan_id": analysis_id,
                    "report_files": {
                        "html": str(latest_analysis / "comprehensive_report.html"),
                        "json": str(latest_analysis / "comprehensive_report.json"),
                        "csv": str(latest_analysis / "comprehensive_report.csv")
                    }
                },
                "report_content": self._get_dynamic_report_content(latest_analysis),
                "report_path": analysis_id  # Use just the analysis_id for consistent download path
            }
                
        except subprocess.TimeoutExpired:
            logger.error("Dynamic Analysis timed out after 10 minutes")
            
            # CRITICAL: Force cleanup after timeout
            if not cleanup_performed:
                logger.error("Timeout occurred - forcing emergency cleanup...")
                self._emergency_cleanup_dynamic()
                cleanup_performed = True
            
            # Try to find partial results
            partial_analysis = self._get_latest_dynamic_analysis_directory()
            has_partial = False
            if partial_analysis and (partial_analysis / "comprehensive_report.json").exists():
                has_partial = True
                logger.info(f"Partial results may be available at: {partial_analysis}")
            
            return {
                "success": False,
                "error": (
                    "Dynamic Analysis timed out after 10 minutes. \n\n"
                    "This usually means:\n"
                    "• The emulator took too long to boot (slow system)\n"
                    "• The app is too complex and took longer than expected\n"
                    "• The app crashed during analysis\n\n"
                    "💡 Try 'Advanced Static Analysis' for guaranteed results on any APK."
                ),
                "has_partial_results": has_partial,
                "partial_analysis_dir": str(partial_analysis) if has_partial else None,
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            logger.error(f"Dynamic Analysis failed with exception: {str(e)}")
            import traceback
            logger.error(traceback.format_exc())
            
            # Ensure cleanup on unexpected exceptions
            if not cleanup_performed:
                logger.error("Exception occurred - forcing emergency cleanup...")
                self._emergency_cleanup_dynamic()
                cleanup_performed = True
            
            return {
                "success": False,
                "error": f"Dynamic Analysis failed: {str(e)}",
                "technical_details": traceback.format_exc()[:500],
                "timestamp": datetime.now().isoformat()
            }
        finally:
            # Final safety net - ensure cleanup always happens
            if not cleanup_performed:
                logger.info("Final cleanup check...")
                self._emergency_cleanup_dynamic()
    
    def _get_latest_dynamic_analysis_directory(self) -> Optional[Path]:
        """Get the path to the latest dynamic analysis directory"""
        try:
            results_dir = self.dynamic_path / "scanned_results"
            if not results_dir.exists():
                return None
            
            # Find the most recent analysis directory (starts with "analysis_")
            analysis_dirs = [d for d in results_dir.iterdir() if d.is_dir() and d.name.startswith("analysis_")]
            if not analysis_dirs:
                return None
            
            return max(analysis_dirs, key=lambda x: x.stat().st_mtime)
        except Exception as e:
            logger.warning(f"Failed to get latest dynamic analysis directory: {e}")
            return None
    
    def _update_dynamic_manifest(self, analysis_dir: Path, apk_metadata: Dict[str, Any], user_id: int = None, error: str = None, partial: bool = False) -> None:
        """Update or create manifest.json in dynamic analysis directory"""
        try:
            manifest_path = analysis_dir / "manifest.json"
            
            # Read existing manifest if it exists (from Dynamic Analyzer)
            existing_data = {}
            if manifest_path.exists():
                try:
                    with open(manifest_path, 'r') as f:
                        existing_data = json.load(f)
                except:
                    pass
            
            # Create manifest data (merge with existing)
            manifest_data = {
                "analysis_type": "Dynamic Analysis",
                "apk_name": apk_metadata.get("apk_name", "Unknown APK"),
                "file_size": apk_metadata.get("file_size", 0),
                "file_path": apk_metadata.get("file_path", ""),
                "upload_timestamp": apk_metadata.get("upload_timestamp", ""),
                "user_id": user_id,
                "created_at": existing_data.get("created_at", datetime.now().isoformat()),
                "updated_at": datetime.now().isoformat(),
                "analysis_directory": analysis_dir.name,
                "status": "failed" if error else ("partial" if partial else "completed"),
                "error": error,
                "partial_results": partial
            }
            
            # Merge with existing data (preserve Dynamic Analyzer's data)
            manifest_data.update(existing_data)
            manifest_data["user_id"] = user_id  # Ensure user_id is set
            if error:
                manifest_data["error"] = error
                manifest_data["status"] = "failed"
            if partial:
                manifest_data["partial_results"] = True
            
            # Write manifest
            with open(manifest_path, 'w') as f:
                json.dump(manifest_data, f, indent=4)
            
            logger.info(f"Created manifest.json for dynamic analysis: {analysis_dir.name}")
            
        except Exception as e:
            logger.error(f"Failed to create dynamic analysis manifest: {e}")
    
    def _load_dynamic_report(self, analysis_dir: Path) -> Dict[str, Any]:
        """Load comprehensive_report.json from dynamic analysis"""
        try:
            json_report_path = analysis_dir / "comprehensive_report.json"
            if json_report_path.exists():
                with open(json_report_path, 'r') as f:
                    return json.load(f)
        except Exception as e:
            logger.warning(f"Failed to load dynamic report JSON: {e}")
        return {}
    
    def _parse_dynamic_results(self, report_data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse dynamic analysis results to extract key metrics"""
        try:
            return {
                "package_name": report_data.get("app_info", {}).get("package_name", "Unknown"),
                "total_api_calls": report_data.get("statistics", {}).get("total_calls", 0),
                "sensitive_apis": report_data.get("statistics", {}).get("by_category", {}).get("sensitive", 0),
                "network_requests": report_data.get("statistics", {}).get("by_category", {}).get("network", 0),
                "file_operations": report_data.get("statistics", {}).get("by_category", {}).get("file", 0),
                "security_score": report_data.get("security_analysis", {}).get("security_score", 0),
                "security_grade": report_data.get("security_analysis", {}).get("security_grade", "N/A"),
                "risk_level": report_data.get("security_analysis", {}).get("risk_level", "Unknown"),
                "findings": {
                    "critical": len([f for f in report_data.get("findings", []) if f.get("severity") == "Critical"]),
                    "high": len([f for f in report_data.get("findings", []) if f.get("severity") == "High"]),
                    "medium": len([f for f in report_data.get("findings", []) if f.get("severity") == "Medium"]),
                    "low": len([f for f in report_data.get("findings", []) if f.get("severity") == "Low"])
                },
                "analysis_duration": report_data.get("metadata", {}).get("total_duration", "Unknown")
            }
        except Exception as e:
            logger.warning(f"Failed to parse dynamic results: {e}")
            return {}
    
    def _get_dynamic_report_content(self, analysis_dir: Path) -> Dict[str, Any]:
        """Get the content of dynamic analysis report files"""
        try:
            content = {}
            
            # Read HTML report
            html_report_path = analysis_dir / "comprehensive_report.html"
            if html_report_path.exists():
                with open(html_report_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content["html_report"] = f.read()
            
            # Read JSON report
            json_report_path = analysis_dir / "comprehensive_report.json"
            if json_report_path.exists():
                with open(json_report_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content["json_report"] = f.read()
            
            # Read CSV report
            csv_report_path = analysis_dir / "comprehensive_report.csv"
            if csv_report_path.exists():
                with open(csv_report_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content["csv_report"] = f.read()
                    
            return content
            
        except Exception as e:
            logger.warning(f"Failed to get dynamic report content: {e}")
            return {}
    
    def _force_cleanup_emulators(self) -> None:
        """
        Force cleanup of any lingering emulator processes
        This prevents 'more than one emulator' errors
        """
        try:
            import psutil
            killed_count = 0
            
            # Kill all qemu-system and emulator processes
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    name = proc.info.get('name', '') or ''
                    cmdline = ' '.join(proc.info.get('cmdline') or [])
                    
                    if 'qemu-system' in name or 'qemu-system' in cmdline or ('emulator' in name and 'avd' in cmdline.lower()):
                        logger.info(f"Force killing stale emulator process: PID {proc.info['pid']} ({name})")
                        proc.kill()
                        proc.wait(timeout=3)
                        killed_count += 1
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.TimeoutExpired):
                    pass
            
            if killed_count > 0:
                logger.info(f"Cleaned up {killed_count} stale emulator process(es)")
                time.sleep(2)  # Give system time to clean up
            
            # Also restart ADB server to clear device list
            try:
                adb_path = Path.home() / "Android" / "Sdk" / "platform-tools" / "adb"
                if adb_path.exists():
                    subprocess.run([str(adb_path), 'kill-server'], capture_output=True, timeout=5)
                    time.sleep(1)
                    subprocess.run([str(adb_path), 'start-server'], capture_output=True, timeout=5)
                    logger.info("ADB server restarted")
            except Exception as e:
                logger.warning(f"Could not restart ADB server: {e}")
                
        except Exception as e:
            logger.warning(f"Error during emulator cleanup: {e}")
    
    def _emergency_cleanup_dynamic(self) -> None:
        """
        Emergency cleanup after failed/timeout dynamic analysis
        Ensures no processes are left running
        """
        logger.info("Performing emergency cleanup of Dynamic Analyzer resources...")
        
        try:
            # 1. Force cleanup emulators
            self._force_cleanup_emulators()
            
            # 2. Kill any Python processes running Dynamic Analyzer CLI
            import psutil
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    cmdline = ' '.join(proc.info.get('cmdline') or [])
                    if 'matrisksDynamicAnalyzer' in cmdline and 'cli.py' in cmdline:
                        logger.info(f"Killing Dynamic Analyzer CLI process: PID {proc.info['pid']}")
                        proc.kill()
                        proc.wait(timeout=3)
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.TimeoutExpired):
                    pass
            
            # 3. Stop any Frida servers
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    if proc.info.get('name') == 'frida-server':
                        logger.info(f"Killing Frida server: PID {proc.info['pid']}")
                        proc.kill()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            
            logger.info("Emergency cleanup completed")
            time.sleep(1)
            
        except Exception as e:
            logger.error(f"Emergency cleanup failed: {e}")
