"""
Analysis service for integrating BasicStatic engine with FastAPI
"""
import os
import json
import subprocess
import tempfile
import shutil
from pathlib import Path
from typing import Dict, Any, Optional
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

class AnalysisService:
    def __init__(self):
        # Path to BasicStatic engine
        self.basicstatic_path = Path(__file__).parent.parent.parent.parent / "matrisksBasicStatic"
        self.python_path = self.basicstatic_path / "venv" / "bin" / "python3"
        self.matrisks_script = self.basicstatic_path / "matrisks.py"
        
    def analyze_apk(self, apk_file_path: str, analysis_type: str = "basic") -> Dict[str, Any]:
        """
        Analyze an APK file using BasicStatic engine
        
        Args:
            apk_file_path: Path to the APK file
            analysis_type: Type of analysis (basic, advanced, dynamic, malware)
            
        Returns:
            Dictionary containing analysis results
        """
        try:
            # Create temporary directory for analysis
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_apk_path = os.path.join(temp_dir, "uploaded.apk")
                
                # Copy APK to temp directory
                shutil.copy2(apk_file_path, temp_apk_path)
                
                # Run BasicStatic analysis
                cmd = [
                    str(self.python_path),
                    str(self.matrisks_script),
                    "-f", temp_apk_path
                ]
                
                logger.info(f"Running analysis command: {' '.join(cmd)}")
                
                # Execute the analysis
                result = subprocess.run(
                    cmd,
                    cwd=str(self.basicstatic_path),
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
                
                return {
                    "success": True,
                    "analysis_type": analysis_type,
                    "timestamp": datetime.now().isoformat(),
                    "raw_output": result.stdout,
                    "results": analysis_results,
                    "report": report_data,
                    "report_content": self._get_report_content(report_data),
                    "report_path": str(self._get_latest_scan_directory()) if self._get_latest_scan_directory() else None
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
            results_dir = self.basicstatic_path / "scanned_results"
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
                    "pdf": str(latest_scan / "report.pdf")
                }
            }
        except Exception as e:
            logger.warning(f"Failed to extract report data: {e}")
            return {}
    
    def _get_report_content(self, report_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Get the content of generated report files (HTML only)
        """
        try:
            content = {}
            
            if not report_data or not report_data.get("report_files"):
                return content
            
            report_files = report_data["report_files"]
            
            # Read HTML report only
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
            
            return content
            
        except Exception as e:
            logger.warning(f"Failed to get report content: {e}")
            return {}
