"""
Matrisks Dynamic Analysis Report Generator
Comprehensive reporting system for dynamic analysis results
Generates JSON, HTML, CSV reports with complete behavioral data
"""

import json
import csv
import os
import hashlib
from datetime import datetime
from typing import Dict, List, Any, Optional
from collections import defaultdict, Counter
from pathlib import Path


class DynamicReportGenerator:
    """
    Comprehensive report generator for dynamic analysis results
    Similar structure to static analyzer's report generator
    """
    
    def __init__(self, analysis_dir: str):
        """
        Initialize report generator with analysis directory
        
        Args:
            analysis_dir: Path to analysis results directory
        """
        self.analysis_dir = Path(analysis_dir)
        self.analysis_name = self.analysis_dir.name
        
        # Load all analysis data
        self.api_calls_data = self._load_json_file('api_calls_*.json')
        self.network_traffic_data = self._load_json_file('network_traffic_*.json')
        self.https_traffic_data = self._load_json_file('https_traffic.json')
        self.logcat_data = self._load_json_file('logcat_analysis.json')
        self.ui_exploration_data = self._load_json_file('ui_exploration.json')
        
        # Calculate security metrics
        self.security_score = self._calculate_security_score()
        self.security_grade = self._get_security_grade(self.security_score)
        self.risk_level = self._calculate_risk_level()
        
    def _load_json_file(self, pattern: str) -> Optional[Dict]:
        """Load JSON file matching pattern"""
        try:
            files = list(self.analysis_dir.glob(pattern))
            if files:
                with open(files[0], 'r', encoding='utf-8') as f:
                    return json.load(f)
        except Exception as e:
            print(f"Warning: Could not load {pattern}: {e}")
        return {}
    
    def _calculate_security_score(self) -> int:
        """
        Calculate overall security score based on findings
        Score: 0-100 (higher is better)
        """
        deductions = 0
        
        # API Call Risk Assessment
        if self.api_calls_data:
            stats = self.api_calls_data.get('statistics', {})
            by_category = stats.get('by_category', {})
            
            # Deduct points for risky API usage
            deductions += by_category.get('runtime', 0) * 5  # Command execution
            deductions += by_category.get('classloader', 0) * 3  # Dynamic code loading
            deductions += min(by_category.get('network', 0), 10) * 2  # Network calls
            deductions += min(by_category.get('crypto', 0), 5) * 1  # Crypto usage
            deductions += by_category.get('contacts', 0) * 3  # Privacy access
            deductions += by_category.get('location', 0) * 4  # Location tracking
            deductions += by_category.get('sms', 0) * 5  # SMS usage
        
        # Logcat Risk Assessment
        if self.logcat_data:
            summary = self.logcat_data.get('summary', {})
            deductions += summary.get('native_crashes', 0) * 3
            deductions += summary.get('camera_accesses', 0) * 2
            deductions += summary.get('microphone_accesses', 0) * 3
            deductions += summary.get('process_execs', 0) * 4
            deductions += summary.get('root_detections', 0) * 5
        
        # Network Security Assessment
        if self.https_traffic_data:
            stats = self.https_traffic_data.get('statistics', {})
            deductions += min(stats.get('total_requests', 0), 20) * 1
            
            # Check for sensitive data leaks
            sensitive = self.https_traffic_data.get('sensitive_data', {})
            deductions += len(sensitive.get('authentication', [])) * 10
            deductions += len(sensitive.get('api_keys', [])) * 15
            deductions += len(sensitive.get('personal_data', [])) * 8
            deductions += len(sensitive.get('data_exfiltration', [])) * 20
        
        # Cap deductions at 100
        deductions = min(deductions, 100)
        score = max(0, 100 - deductions)
        
        return score
    
    def _get_security_grade(self, score: int) -> str:
        """Convert security score to letter grade"""
        if score >= 90:
            return 'A'
        elif score >= 80:
            return 'B'
        elif score >= 70:
            return 'C'
        elif score >= 60:
            return 'D'
        else:
            return 'F'
    
    def _calculate_risk_level(self) -> str:
        """Determine overall risk level"""
        if self.security_score >= 80:
            return 'Low'
        elif self.security_score >= 60:
            return 'Medium'
        elif self.security_score >= 40:
            return 'High'
        else:
            return 'Critical'
    
    def _extract_app_info(self) -> Dict[str, Any]:
        """Extract app information from analysis data"""
        package_name = 'Unknown'
        
        # Try to get package name from various sources
        if self.ui_exploration_data:
            package_name = self.ui_exploration_data.get('package_name', package_name)
        elif self.logcat_data:
            package_name = self.logcat_data.get('package_name', package_name)
        elif self.api_calls_data:
            # Try to extract from file operations
            sensitive = self.api_calls_data.get('sensitive_behaviors', {})
            file_ops = sensitive.get('file_operations', [])
            if file_ops:
                path = file_ops[0].get('path', '')
                if '/data/user/0/' in path:
                    package_name = path.split('/data/user/0/')[1].split('/')[0]
        
        # Extract timestamp from directory name
        timestamp_str = self.analysis_name.split('_')[-2:]
        timestamp = '_'.join(timestamp_str) if len(timestamp_str) == 2 else 'Unknown'
        
        return {
            'package_name': package_name,
            'analysis_id': self.analysis_name,
            'analysis_timestamp': timestamp,
            'analysis_type': 'dynamic_analysis'
        }
    
    def _get_api_analysis_section(self) -> Dict[str, Any]:
        """Generate comprehensive API calls analysis section"""
        if not self.api_calls_data:
            return {}
        
        stats = self.api_calls_data.get('statistics', {})
        by_category = stats.get('by_category', {})
        detailed = stats.get('detailed', {})
        
        return {
            'total_api_calls': stats.get('total_calls', 0),
            'duration_seconds': stats.get('duration_seconds', 0),
            'calls_per_second': stats.get('calls_per_second', 0),
            'by_category': by_category,
            'detailed_breakdown': detailed,
            'top_api_types': self._get_top_api_types(detailed, limit=10)
        }
    
    def _get_top_api_types(self, detailed: Dict, limit: int = 10) -> List[Dict]:
        """Get top API call types by frequency"""
        # Filter out total_ prefixed keys
        api_types = {k: v for k, v in detailed.items() if not k.startswith('total_')}
        # Sort by count descending
        sorted_types = sorted(api_types.items(), key=lambda x: x[1], reverse=True)[:limit]
        return [{'type': k, 'count': v} for k, v in sorted_types]
    
    def _get_sensitive_behaviors_section(self) -> Dict[str, Any]:
        """Analyze sensitive behaviors detected"""
        if not self.api_calls_data:
            return {}
        
        sensitive = self.api_calls_data.get('sensitive_behaviors', {})
        
        return {
            'network_communication': {
                'total_calls': len(sensitive.get('network_communication', [])),
                'unique_domains': self._extract_unique_domains(sensitive.get('network_communication', [])),
                'calls': sensitive.get('network_communication', [])
            },
            'file_operations': {
                'total_operations': len(sensitive.get('file_operations', [])),
                'file_writes': len([f for f in sensitive.get('file_operations', []) if f.get('action') == 'FILE_WRITE']),
                'file_reads': len([f for f in sensitive.get('file_operations', []) if f.get('action') == 'FILE_READ']),
                'file_deletes': len([f for f in sensitive.get('file_operations', []) if f.get('action') == 'FILE_DELETE']),
                'sensitive_paths': self._extract_sensitive_paths(sensitive.get('file_operations', []))
            },
            'cryptography': {
                'total_operations': len(sensitive.get('cryptography', [])),
                'algorithms_used': self._extract_crypto_algorithms(sensitive.get('cryptography', [])),
                'operations': sensitive.get('cryptography', [])
            },
            'contacts_access': {
                'total_queries': len(sensitive.get('contacts_access', [])),
                'queries': sensitive.get('contacts_access', [])
            },
            'dynamic_loading': {
                'total_loads': len(sensitive.get('dynamic_loading', [])),
                'loaded_paths': [d.get('dexPath') for d in sensitive.get('dynamic_loading', [])],
                'loads': sensitive.get('dynamic_loading', [])
            },
            'command_execution': {
                'total_commands': len(sensitive.get('command_execution', [])),
                'commands': sensitive.get('command_execution', [])
            }
        }
    
    def _extract_unique_domains(self, network_calls: List[Dict]) -> List[str]:
        """Extract unique domains from network calls"""
        domains = set()
        for call in network_calls:
            url = call.get('url', '')
            if '://' in url:
                domain = url.split('://')[1].split('/')[0]
                domains.add(domain)
        return sorted(list(domains))
    
    def _extract_sensitive_paths(self, file_ops: List[Dict]) -> List[str]:
        """Extract sensitive file paths"""
        sensitive_patterns = [
            'shared_prefs',
            'databases',
            'files',
            'cache',
            '/sdcard',
            '/external'
        ]
        
        sensitive_paths = set()
        for op in file_ops[:50]:  # Limit to first 50
            path = op.get('path', '')
            if any(pattern in path for pattern in sensitive_patterns):
                sensitive_paths.add(path)
        
        return sorted(list(sensitive_paths))
    
    def _extract_crypto_algorithms(self, crypto_ops: List[Dict]) -> Dict[str, int]:
        """Count crypto algorithms used"""
        algorithms = Counter()
        for op in crypto_ops:
            algo = op.get('algorithm', 'Unknown')
            algorithms[algo] += 1
        return dict(algorithms)
    
    def _get_network_analysis_section(self) -> Dict[str, Any]:
        """Generate network traffic analysis section"""
        network_analysis = {}
        
        # Regular network traffic
        if self.network_traffic_data:
            stats = self.network_traffic_data.get('statistics', {})
            network_analysis['tcp_udp_traffic'] = {
                'total_events': stats.get('total_events', 0),
                'connections': stats.get('connections', 0),
                'http_requests': stats.get('http_requests', 0),
                'dns_queries': stats.get('dns_queries', 0),
                'unique_hosts': stats.get('unique_hosts', 0),
                'hosts': stats.get('hosts', [])
            }
        
        # HTTPS traffic
        if self.https_traffic_data:
            stats = self.https_traffic_data.get('statistics', {})
            network_analysis['https_traffic'] = {
                'total_requests': stats.get('total_requests', 0),
                'total_responses': stats.get('total_responses', 0),
                'unique_domains': stats.get('unique_domains', 0),
                'requests_per_second': stats.get('requests_per_second', 0),
                'methods_used': stats.get('by_method', {})
            }
            
            # Add sensitive data findings
            sensitive = self.https_traffic_data.get('sensitive_data', {})
            network_analysis['sensitive_data_detected'] = {
                'authentication_tokens': len(sensitive.get('authentication', [])),
                'api_keys': len(sensitive.get('api_keys', [])),
                'personal_data': len(sensitive.get('personal_data', [])),
                'suspicious_urls': len(sensitive.get('suspicious_urls', [])),
                'data_exfiltration': len(sensitive.get('data_exfiltration', [])),
                'details': sensitive
            }
        
        return network_analysis
    
    def _get_system_monitoring_section(self) -> Dict[str, Any]:
        """Generate system monitoring analysis section"""
        if not self.logcat_data:
            return {}
        
        summary = self.logcat_data.get('summary', {})
        details = self.logcat_data.get('details', {})
        
        return {
            'summary': summary,
            'permissions_requested': {
                'count': summary.get('permissions_requested', 0),
                'permissions': details.get('permissions_requested', [])
            },
            'intents_broadcasted': {
                'count': summary.get('intents_broadcasted', 0),
                'intents': details.get('intents_broadcasted', [])
            },
            'services_started': {
                'count': summary.get('services_started', 0),
                'services': details.get('services_started', [])
            },
            'native_crashes': {
                'count': summary.get('native_crashes', 0),
                'crashes': details.get('native_crashes', [])
            },
            'camera_accesses': {
                'count': summary.get('camera_accesses', 0),
                'events': details.get('camera_accesses', [])
            },
            'microphone_accesses': {
                'count': summary.get('microphone_accesses', 0),
                'events': details.get('microphone_accesses', [])
            },
            'process_executions': {
                'count': summary.get('process_execs', 0),
                'commands': details.get('process_execs', [])
            },
            'root_detections': {
                'count': summary.get('root_detections', 0),
                'events': details.get('root_detections', [])
            }
        }
    
    def _get_ui_exploration_section(self) -> Dict[str, Any]:
        """Generate UI exploration analysis section"""
        if not self.ui_exploration_data:
            return {}
        
        return {
            'total_actions': self.ui_exploration_data.get('total_actions', 0),
            'activities_explored': self.ui_exploration_data.get('activities_explored', 0),
            'screenshots_captured': self.ui_exploration_data.get('screenshots', 0),
            'duration_seconds': self.ui_exploration_data.get('duration', 0),
            'exploration_mode': self.ui_exploration_data.get('exploration_mode', 'unknown'),
            'actions': self.ui_exploration_data.get('actions', []),
            'network_buttons_clicked': self.ui_exploration_data.get('network_buttons_clicked', 0)
        }
    
    def _categorize_risks(self) -> Dict[str, List[Dict]]:
        """Categorize all findings by risk level"""
        risks = {
            'critical': [],
            'high': [],
            'medium': [],
            'low': [],
            'info': []
        }
        
        # Analyze API calls for risks
        if self.api_calls_data:
            sensitive = self.api_calls_data.get('sensitive_behaviors', {})
            
            # Command execution = Critical
            for cmd in sensitive.get('command_execution', []):
                risks['critical'].append({
                    'category': 'Command Execution',
                    'finding': f"Executed: {cmd.get('command', 'Unknown')}",
                    'timestamp': cmd.get('timestamp', 0)
                })
            
            # Dynamic code loading = High
            for dex in sensitive.get('dynamic_loading', []):
                risks['high'].append({
                    'category': 'Dynamic Code Loading',
                    'finding': f"Loaded: {dex.get('dexPath', 'Unknown')}",
                    'timestamp': dex.get('timestamp', 0)
                })
            
            # Network communication = Medium
            for net in sensitive.get('network_communication', [])[:10]:  # Limit to 10
                risks['medium'].append({
                    'category': 'Network Communication',
                    'finding': f"Connected to: {net.get('url', 'Unknown')}",
                    'timestamp': net.get('timestamp', 0)
                })
        
        # Analyze system events for risks
        if self.logcat_data:
            details = self.logcat_data.get('details', {})
            
            # Native crashes = High
            for crash in details.get('native_crashes', []):
                risks['high'].append({
                    'category': 'Native Crash',
                    'finding': crash.get('log', 'Crash detected'),
                    'timestamp': crash.get('timestamp', 0)
                })
            
            # Camera/Mic access = Medium
            for camera in details.get('camera_accesses', []):
                risks['medium'].append({
                    'category': 'Camera Access',
                    'finding': camera.get('log', 'Camera accessed'),
                    'timestamp': camera.get('timestamp', 0)
                })
        
        # Analyze HTTPS traffic for risks
        if self.https_traffic_data:
            sensitive = self.https_traffic_data.get('sensitive_data', {})
            
            # Data exfiltration = Critical
            for exfil in sensitive.get('data_exfiltration', []):
                risks['critical'].append({
                    'category': 'Data Exfiltration',
                    'finding': f"Suspicious data sent to: {exfil.get('url', 'Unknown')}",
                    'details': exfil
                })
            
            # API keys = High
            for api_key in sensitive.get('api_keys', []):
                risks['high'].append({
                    'category': 'API Key Exposure',
                    'finding': f"API key found in: {api_key.get('location', 'Unknown')}",
                    'details': api_key
                })
        
        return risks
    
    def generate_json_report(self) -> Dict[str, Any]:
        """
        Generate comprehensive JSON report
        """
        report = {
            'report_info': {
                'generated_by': 'Matrisks Dynamic Analysis Framework',
                'generated_at': datetime.utcnow().isoformat() + 'Z',
                'report_version': '1.0',
                'analysis_id': self.analysis_name,
                'analyzer_type': 'dynamic'
            },
            
            'app_info': self._extract_app_info(),
            
            'security_assessment': {
                'security_score': self.security_score,
                'security_grade': self.security_grade,
                'risk_level': self.risk_level,
                'summary': f"Security score: {self.security_score}/100 (Grade: {self.security_grade})"
            },
            
            'api_analysis': self._get_api_analysis_section(),
            
            'sensitive_behaviors': self._get_sensitive_behaviors_section(),
            
            'network_analysis': self._get_network_analysis_section(),
            
            'system_monitoring': self._get_system_monitoring_section(),
            
            'ui_exploration': self._get_ui_exploration_section(),
            
            'risk_categorization': self._categorize_risks(),
            
            'raw_data': {
                'api_calls': self.api_calls_data,
                'network_traffic': self.network_traffic_data,
                'https_traffic': self.https_traffic_data,
                'logcat': self.logcat_data,
                'ui_exploration': self.ui_exploration_data
            }
        }
        
        return report
    
    def save_json_report(self, output_path: str = None) -> str:
        """Save JSON report to file"""
        if output_path is None:
            output_path = self.analysis_dir / 'comprehensive_report.json'
        else:
            output_path = Path(output_path)
        
        report = self.generate_json_report()
        
        # Ensure directory exists
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        print(f"✓ JSON report saved: {output_path}")
        return str(output_path)
    
    def generate_csv_report(self) -> List[List[str]]:
        """Generate comprehensive CSV with all findings"""
        csv_data = []
        
        # Header row
        headers = [
            'Timestamp',
            'Category',
            'Type',
            'Action',
            'Risk Level',
            'Details',
            'Location/URL',
            'Algorithm/Method',
            'Additional Info'
        ]
        csv_data.append(headers)
        
        # API Calls
        if self.api_calls_data:
            api_calls = self.api_calls_data.get('api_calls', [])
            for call in api_calls:
                details = call.get('details', {})
                row = [
                    str(call.get('timestamp', '')),
                    'API Call',
                    call.get('category', 'Unknown'),
                    call.get('action', 'Unknown'),
                    self._assess_api_risk(call),
                    json.dumps(details, ensure_ascii=False)[:200],
                    details.get('url') or details.get('path') or details.get('uri') or 'N/A',
                    details.get('algorithm') or details.get('method') or 'N/A',
                    call.get('stacktrace', '')[:100]
                ]
                csv_data.append(row)
        
        # System Events
        if self.logcat_data:
            details = self.logcat_data.get('details', {})
            
            # Native crashes
            for crash in details.get('native_crashes', []):
                csv_data.append([
                    str(crash.get('timestamp', '')),
                    'System Event',
                    'Native Crash',
                    'CRASH',
                    'High',
                    crash.get('log', ''),
                    'N/A',
                    'N/A',
                    'Application crashed'
                ])
            
            # Camera accesses
            for camera in details.get('camera_accesses', []):
                csv_data.append([
                    str(camera.get('timestamp', '')),
                    'Privacy',
                    'Camera Access',
                    'CAMERA',
                    'Medium',
                    camera.get('log', ''),
                    'N/A',
                    'N/A',
                    'Camera service started'
                ])
        
        # HTTPS Traffic
        if self.https_traffic_data:
            requests = self.https_traffic_data.get('requests', [])
            for req in requests[:100]:  # Limit to 100
                csv_data.append([
                    str(req.get('timestamp', '')),
                    'Network',
                    'HTTPS Request',
                    req.get('method', 'Unknown'),
                    'Medium',
                    req.get('url', ''),
                    req.get('url', ''),
                    req.get('method', ''),
                    f"Status: {req.get('status_code', 'N/A')}"
                ])
        
        return csv_data
    
    def _assess_api_risk(self, api_call: Dict) -> str:
        """Assess risk level of an API call"""
        category = api_call.get('category', '').lower()
        action = api_call.get('action', '').lower()
        
        if category == 'runtime' or 'exec' in action:
            return 'Critical'
        elif category == 'classloader' or 'dex' in action:
            return 'High'
        elif category in ['contacts', 'location', 'sms']:
            return 'High'
        elif category in ['network', 'https']:
            return 'Medium'
        elif category == 'crypto':
            return 'Low'
        else:
            return 'Info'
    
    def save_csv_report(self, output_path: str = None) -> str:
        """Save CSV report"""
        if output_path is None:
            output_path = self.analysis_dir / 'comprehensive_report.csv'
        else:
            output_path = Path(output_path)
        
        csv_data = self.generate_csv_report()
        
        # Ensure directory exists
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f, quoting=csv.QUOTE_ALL)
            writer.writerows(csv_data)
        
        print(f"✓ CSV report saved: {output_path}")
        return str(output_path)
    
    def _escape_html(self, text: str) -> str:
        """Escape HTML special characters"""
        if not isinstance(text, str):
            text = str(text)
        return (text
                .replace('&', '&amp;')
                .replace('<', '&lt;')
                .replace('>', '&gt;')
                .replace('"', '&quot;')
                .replace("'", '&#39;'))
    
    def _get_severity_color(self, severity: str) -> str:
        """Get color for severity level matching static analyzer"""
        colors = {
            'Critical': '#d32f2f',  # Red
            'High': '#d32f2f',      # Red  
            'Warning': '#f57c00',   # Orange
            'Medium': '#f57c00',    # Orange
            'Notice': '#1976d2',    # Blue
            'Low': '#1976d2',       # Blue
            'Info': '#616161'       # Gray
        }
        return colors.get(severity, '#616161')
    
    def _get_grade_color(self, grade: str) -> str:
        """Get color for security grade"""
        colors = {
            'A': '#2e7d32',  # Green
            'B': '#558b2f',  # Light green
            'C': '#f57c00',  # Orange
            'D': '#e64a19',  # Deep orange
            'F': '#c62828'   # Deep red
        }
        return colors.get(grade, '#616161')
    
    def _generate_api_findings_table(self, report_data: dict) -> str:
        """Generate detailed API findings table"""
        api_calls = []
        if self.api_calls_data and isinstance(self.api_calls_data, dict):
            api_calls = self.api_calls_data.get('api_calls', [])
        elif self.api_calls_data and isinstance(self.api_calls_data, list):
            api_calls = self.api_calls_data
        
        if not api_calls:
            return '<p class="no-findings">No API calls captured during analysis.</p>'
        
        rows_html = ""
        for idx, call in enumerate(api_calls[:100]):  # Limit to 100 for performance
            category = call.get('category', 'unknown')
            api_type = call.get('type', 'N/A')
            action = call.get('action', 'N/A')
            timestamp = call.get('timestamp', 'N/A')
            details = call.get('details', {})
            
            # Determine severity
            risk = self._categorize_risk_simple(category, action)
            severity_color = self._get_severity_color(risk)
            
            # Format details
            details_str = ', '.join([f"{k}: {v}" for k, v in details.items() if k not in ['stack_trace']])[:200]
            stack_trace = details.get('stack_trace', '')
            
            unique_id = f"api-{idx}"
            
            rows_html += f"""
            <tr class="finding-row" onclick="toggleDetails('{unique_id}')">
                <td class="severity-cell">
                    <span class="severity-badge" style="background-color: {severity_color}">{risk}</span>
                </td>
                <td class="summary-cell">
                    <div class="finding-summary">{self._escape_html(action)}</div>
                    <div class="finding-meta">
                        <span class="meta-item">Category: {self._escape_html(category)}</span>
                        <span class="meta-item">Type: {self._escape_html(api_type)}</span>
                        <span class="meta-item">Time: {self._escape_html(timestamp)}</span>
                    </div>
                </td>
                <td class="expand-cell">
                    <span class="expand-icon" id="icon-{unique_id}">▼</span>
                </td>
            </tr>
            <tr class="details-row" id="details-{unique_id}">
                <td colspan="3">
                    <div class="finding-details">
                        <div class="detail-section">
                            <h4>API Details</h4>
                            <p>{self._escape_html(details_str) if details_str else 'No additional details'}</p>
                        </div>
                        {f'<div class="detail-section"><h4>Stack Trace</h4><pre class="code-block">{self._escape_html(str(stack_trace)[:500])}</pre></div>' if stack_trace else ''}
                        <div class="detail-section">
                            <h4>Security Impact</h4>
                            <p>{self._get_risk_description(category, action)}</p>
                        </div>
                    </div>
                </td>
            </tr>
            """
        
        if len(api_calls) > 100:
            rows_html += f"""
            <tr>
                <td colspan="3" style="text-align: center; padding: 1rem; background: #fffbeb; color: #92400e; font-weight: 600;">
                    Showing first 100 of {len(api_calls)} API calls. See JSON report for complete data.
                </td>
            </tr>
            """
        
        table_html = f"""
        <div class="findings-table-container">
            <table class="findings-table">
                <thead>
                    <tr>
                        <th class="severity-col" style="width: 120px;">Risk Level</th>
                        <th class="summary-col">API Call Details</th>
                        <th class="expand-col" style="width: 40px;"></th>
                    </tr>
                </thead>
                <tbody>
                    {rows_html}
                </tbody>
            </table>
        </div>
        """
        
        return table_html
    
    def _generate_network_findings_table(self, report_data: dict) -> str:
        """Generate network activity findings table"""
        tcp_connections = self.network_traffic_data if isinstance(self.network_traffic_data, list) else []
        https_requests = self.https_traffic_data if isinstance(self.https_traffic_data, list) else []
        
        if not tcp_connections and not https_requests:
            return '<p class="no-findings">No network activity captured during analysis.</p>'
        
        rows_html = ""
        idx = 0
        
        # HTTPS requests
        for req in https_requests[:50]:
            url = req.get('url', 'N/A')
            method = req.get('method', 'N/A')
            timestamp = req.get('timestamp', 'N/A')
            response_code = req.get('response_code', 'N/A')
            
            # Check for sensitive data
            has_sensitive = any(word in url.lower() for word in ['password', 'token', 'key', 'secret', 'api_key'])
            risk = 'High' if has_sensitive else 'Medium'
            severity_color = self._get_severity_color(risk)
            
            unique_id = f"network-{idx}"
            idx += 1
            
            rows_html += f"""
            <tr class="finding-row" onclick="toggleDetails('{unique_id}')">
                <td class="severity-cell">
                    <span class="severity-badge" style="background-color: {severity_color}">{risk}</span>
                </td>
                <td class="summary-cell">
                    <div class="finding-summary">{self._escape_html(method)} {self._escape_html(url[:80])}</div>
                    <div class="finding-meta">
                        <span class="meta-item">Response: {response_code}</span>
                        <span class="meta-item">Time: {self._escape_html(timestamp)}</span>
                    </div>
                </td>
                <td class="expand-cell">
                    <span class="expand-icon" id="icon-{unique_id}">▼</span>
                </td>
            </tr>
            <tr class="details-row" id="details-{unique_id}">
                <td colspan="3">
                    <div class="finding-details">
                        <div class="detail-section">
                            <h4>Request Details</h4>
                            <p><strong>URL:</strong> {self._escape_html(url)}</p>
                            <p><strong>Method:</strong> {method}</p>
                            <p><strong>Response Code:</strong> {response_code}</p>
                        </div>
                        {f'<div class="detail-section"><h4>Security Concern</h4><p style="color: #d32f2f; font-weight: 600;">URL contains sensitive keywords that may indicate exposure of credentials or API keys.</p></div>' if has_sensitive else ''}
                    </div>
                </td>
            </tr>
            """
        
        # TCP connections
        for conn in tcp_connections[:50]:
            host = conn.get('host', 'N/A')
            port = conn.get('port', 'N/A')
            timestamp = conn.get('timestamp', 'N/A')
            
            risk = 'Medium'
            severity_color = self._get_severity_color(risk)
            
            unique_id = f"network-{idx}"
            idx += 1
            
            rows_html += f"""
            <tr class="finding-row" onclick="toggleDetails('{unique_id}')">
                <td class="severity-cell">
                    <span class="severity-badge" style="background-color: {severity_color}">{risk}</span>
                </td>
                <td class="summary-cell">
                    <div class="finding-summary">TCP Connection to {self._escape_html(host)}:{port}</div>
                    <div class="finding-meta">
                        <span class="meta-item">Time: {self._escape_html(timestamp)}</span>
                    </div>
                </td>
                <td class="expand-cell">
                    <span class="expand-icon" id="icon-{unique_id}">▼</span>
                </td>
            </tr>
            <tr class="details-row" id="details-{unique_id}">
                <td colspan="3">
                    <div class="finding-details">
                        <div class="detail-section">
                            <h4>Connection Details</h4>
                            <p><strong>Host:</strong> {self._escape_html(host)}</p>
                            <p><strong>Port:</strong> {port}</p>
                        </div>
                    </div>
                </td>
            </tr>
            """
        
        table_html = f"""
        <div class="findings-table-container">
            <table class="findings-table">
                <thead>
                    <tr>
                        <th class="severity-col" style="width: 120px;">Risk Level</th>
                        <th class="summary-col">Network Activity</th>
                        <th class="expand-col" style="width: 40px;"></th>
                    </tr>
                </thead>
                <tbody>
                    {rows_html}
                </tbody>
            </table>
        </div>
        """
        
        return table_html
    
    def _generate_file_findings_table(self, report_data: dict) -> str:
        """Generate file operations findings table"""
        api_calls = []
        if self.api_calls_data and isinstance(self.api_calls_data, dict):
            api_calls = self.api_calls_data.get('api_calls', [])
        elif self.api_calls_data and isinstance(self.api_calls_data, list):
            api_calls = self.api_calls_data
        file_ops = [call for call in api_calls if call.get('category') == 'file']
        
        if not file_ops:
            return '<p class="no-findings">No file operations detected during analysis.</p>'
        
        rows_html = ""
        for idx, call in enumerate(file_ops[:50]):
            action = call.get('action', 'N/A')
            timestamp = call.get('timestamp', 'N/A')
            details = call.get('details', {})
            path = details.get('path', details.get('file', 'N/A'))
            
            risk = 'Medium'
            severity_color = self._get_severity_color(risk)
            
            unique_id = f"file-{idx}"
            
            rows_html += f"""
            <tr class="finding-row" onclick="toggleDetails('{unique_id}')">
                <td class="severity-cell">
                    <span class="severity-badge" style="background-color: {severity_color}">{risk}</span>
                </td>
                <td class="summary-cell">
                    <div class="finding-summary">{self._escape_html(action)}</div>
                    <div class="finding-meta">
                        <span class="meta-item">Path: {self._escape_html(str(path)[:60])}</span>
                        <span class="meta-item">Time: {self._escape_html(timestamp)}</span>
                    </div>
                </td>
                <td class="expand-cell">
                    <span class="expand-icon" id="icon-{unique_id}">▼</span>
                </td>
            </tr>
            <tr class="details-row" id="details-{unique_id}">
                <td colspan="3">
                    <div class="finding-details">
                        <div class="detail-section">
                            <h4>File Operation Details</h4>
                            <p><strong>Action:</strong> {self._escape_html(action)}</p>
                            <p><strong>Path:</strong> <code>{self._escape_html(str(path))}</code></p>
                        </div>
                    </div>
                </td>
            </tr>
            """
        
        table_html = f"""
        <div class="findings-table-container">
            <table class="findings-table">
                <thead>
                    <tr>
                        <th class="severity-col" style="width: 120px;">Risk Level</th>
                        <th class="summary-col">File Operation</th>
                        <th class="expand-col" style="width: 40px;"></th>
                    </tr>
                </thead>
                <tbody>
                    {rows_html}
                </tbody>
            </table>
        </div>
        """
        
        return table_html
    
    def _generate_system_findings_table(self, report_data: dict) -> str:
        """Generate system events findings table"""
        logcat = self.logcat_data if self.logcat_data else {}
        events = []
        
        # Collect all events
        for event_type in ['crashes', 'camera_events', 'mic_events', 'permission_requests', 'intent_events']:
            for event in logcat.get(event_type, []):
                events.append({
                    'type': event_type.replace('_', ' ').title(),
                    'data': event
                })
        
        if not events:
            return '<p class="no-findings">No critical system events detected during analysis.</p>'
        
        rows_html = ""
        for idx, event in enumerate(events[:50]):
            event_type = event['type']
            data = event['data']
            
            # Determine risk based on event type
            if 'crash' in event_type.lower():
                risk = 'High'
            elif 'camera' in event_type.lower() or 'mic' in event_type.lower():
                risk = 'Medium'
            else:
                risk = 'Low'
            
            severity_color = self._get_severity_color(risk)
            
            unique_id = f"system-{idx}"
            
            rows_html += f"""
            <tr class="finding-row" onclick="toggleDetails('{unique_id}')">
                <td class="severity-cell">
                    <span class="severity-badge" style="background-color: {severity_color}">{risk}</span>
                </td>
                <td class="summary-cell">
                    <div class="finding-summary">{self._escape_html(event_type)}</div>
                    <div class="finding-meta">
                        <span class="meta-item">{self._escape_html(str(data)[:80])}</span>
                    </div>
                </td>
                <td class="expand-cell">
                    <span class="expand-icon" id="icon-{unique_id}">▼</span>
                </td>
            </tr>
            <tr class="details-row" id="details-{unique_id}">
                <td colspan="3">
                    <div class="finding-details">
                        <div class="detail-section">
                            <h4>Event Details</h4>
                            <pre class="code-block">{self._escape_html(str(data)[:500])}</pre>
                        </div>
                    </div>
                </td>
            </tr>
            """
        
        table_html = f"""
        <div class="findings-table-container">
            <table class="findings-table">
                <thead>
                    <tr>
                        <th class="severity-col" style="width: 120px;">Risk Level</th>
                        <th class="summary-col">System Event</th>
                        <th class="expand-col" style="width: 40px;"></th>
                    </tr>
                </thead>
                <tbody>
                    {rows_html}
                </tbody>
            </table>
        </div>
        """
        
        return table_html
    
    def _get_risk_description(self, category: str, action: str) -> str:
        """Get risk description for API call"""
        descriptions = {
            'runtime': 'Runtime operations like reflection and dynamic code loading can be used to evade detection and execute malicious code.',
            'classloader': 'Custom class loading may indicate code obfuscation or dynamic code execution techniques.',
            'network': 'Network calls should be reviewed to ensure they use secure protocols and do not leak sensitive data.',
            'crypto': 'Cryptographic operations should use strong algorithms and proper key management practices.',
            'file': 'File operations should be reviewed to ensure they do not expose sensitive data or create security vulnerabilities.',
            'sms': 'SMS operations can be used for phishing, premium rate fraud, or unauthorized communication.',
            'location': 'Location tracking raises privacy concerns and should be necessary for app functionality.',
            'contacts': 'Access to contacts should be justified and users should be informed about data usage.'
        }
        return descriptions.get(category, 'Review this API call to ensure it follows security best practices.')
    
    def _categorize_risk_simple(self, category: str, action: str) -> str:
        """Simple risk categorization for individual API calls"""
        action_lower = action.lower() if action else ''
        
        if category == 'runtime' or 'reflect' in action_lower or 'invoke' in action_lower:
            return 'Critical'
        elif category == 'classloader' or 'dex' in action_lower or 'loadclass' in action_lower:
            return 'High'
        elif category in ['sms', 'location', 'contacts']:
            return 'High'
        elif category in ['network', 'https']:
            return 'Medium'
        elif category in ['crypto', 'file']:
            return 'Medium'
        else:
            return 'Low'
    
    def generate_html_report(self) -> str:
        """Generate comprehensive HTML report matching Advanced Static analyzer design"""
        report_data = self.generate_json_report()
        
        # Prepare security data
        security = report_data['security_assessment']
        app_info = report_data['app_info']
        report_info = report_data['report_info']
        
        grade_color = self._get_grade_color(security['security_grade'])
        
        # Determine risk level and class
        risk_counts = report_data['risk_categorization']
        critical_count = len(risk_counts.get('critical', []))
        high_count = len(risk_counts.get('high', []))
        medium_count = len(risk_counts.get('medium', []))
        low_count = len(risk_counts.get('low', []))
        info_count = len(risk_counts.get('info', []))
        
        total_issues = critical_count + high_count + medium_count + low_count + info_count
        
        if critical_count > 0 or high_count > 3:
            risk_level = "HIGH RISK"
            risk_class = "risk-high"
            risk_message = "Critical security concerns detected. Immediate review required."
        elif medium_count > 5:
            risk_level = "MEDIUM RISK"
            risk_class = "risk-medium"
            risk_message = "Multiple warnings found. Review and address soon."
        elif medium_count > 0:
            risk_level = "LOW-MEDIUM RISK"
            risk_class = "risk-low-medium"
            risk_message = "Some security concerns identified. Review recommended."
        else:
            risk_level = "LOW RISK"
            risk_class = "risk-low"
            risk_message = "No critical issues detected. Continue monitoring."
        
        # Calculate percentages for progress bars
        critical_pct = (critical_count * 100 // total_issues) if total_issues > 0 else 0
        high_pct = (high_count * 100 // total_issues) if total_issues > 0 else 0
        medium_pct = (medium_count * 100 // total_issues) if total_issues > 0 else 0
        low_pct = (low_count * 100 // total_issues) if total_issues > 0 else 0
        
        # Generate API findings table
        api_findings_html = self._generate_api_findings_table(report_data)
        
        # Generate network findings table
        network_findings_html = self._generate_network_findings_table(report_data)
        
        # Generate file operations table
        file_findings_html = self._generate_file_findings_table(report_data)
        
        # Generate system events table
        system_findings_html = self._generate_system_findings_table(report_data)
        
        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Matrisks Dynamic Analysis - {self._escape_html(app_info.get('package_name', 'Report'))}</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@3.9.1/dist/chart.min.js"></script>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: #ffffff;
            color: #212121;
            line-height: 1.6;
        }}
        
        .header {{
            background: #000000;
            color: #ffffff;
            padding: 2.5rem 2rem;
            border-bottom: 4px solid #e0e0e0;
        }}
        
        .header h1 {{
            font-size: 2rem;
            font-weight: 600;
            margin-bottom: 0.5rem;
            letter-spacing: -0.5px;
        }}
        
        .header .subtitle {{
            font-size: 1rem;
            opacity: 0.8;
            font-weight: 400;
        }}
        
        .header .report-meta {{
            margin-top: 0.5rem;
            font-size: 0.875rem;
            opacity: 0.7;
        }}
        
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            padding: 2rem;
        }}
        
        .section {{
            background: #ffffff;
            border: 1px solid #e0e0e0;
            border-radius: 4px;
            padding: 2rem;
            margin-bottom: 2rem;
        }}
        
        .section h2 {{
            color: #000000;
            font-size: 1.5rem;
            font-weight: 600;
            margin-bottom: 0.5rem;
            padding-bottom: 0.5rem;
            border-bottom: 2px solid #000000;
        }}
        
        .section-description {{
            color: #666666;
            margin-bottom: 1.5rem;
            font-size: 0.95rem;
        }}
        
        .executive-summary {{
            margin-bottom: 2rem;
            background: #fafafa;
            border-radius: 8px;
            overflow: hidden;
        }}
        
        .summary-header {{
            background: linear-gradient(135deg, #2c2c2c 0%, #000000 100%);
            color: #ffffff;
            padding: 2rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 4px solid #e0e0e0;
        }}
        
        .header-content {{
            flex: 1;
        }}
        
        .app-name {{
            font-size: 1.75rem;
            font-weight: 700;
            margin: 0 0 0.5rem 0;
            color: #ffffff;
        }}
        
        .version-info {{
            font-size: 0.95rem;
            opacity: 0.85;
            font-family: 'Courier New', monospace;
        }}
        
        .risk-status {{
            text-align: right;
        }}
        
        .risk-badge-large {{
            font-size: 1.25rem;
            font-weight: 700;
            padding: 0.75rem 1.5rem;
            border-radius: 6px;
            display: inline-block;
            margin-bottom: 0.5rem;
            letter-spacing: 1px;
        }}
        
        .risk-high .risk-badge-large {{
            background: #d32f2f;
            box-shadow: 0 0 20px rgba(211, 47, 47, 0.4);
        }}
        
        .risk-medium .risk-badge-large {{
            background: #f57c00;
            box-shadow: 0 0 20px rgba(245, 124, 0, 0.4);
        }}
        
        .risk-low-medium .risk-badge-large {{
            background: #1976d2;
            box-shadow: 0 0 20px rgba(25, 118, 210, 0.4);
        }}
        
        .risk-low .risk-badge-large {{
            background: #2e7d32;
            box-shadow: 0 0 20px rgba(46, 125, 50, 0.4);
        }}
        
        .risk-description {{
            font-size: 0.875rem;
            opacity: 0.9;
        }}
        
        .summary-main {{
            padding: 2rem;
        }}
        
        .grade-section {{
            display: grid;
            grid-template-columns: 350px 1fr;
            gap: 2rem;
        }}
        
        .grade-card {{
            background: #ffffff;
            border: 2px solid #e0e0e0;
            border-radius: 8px;
            padding: 2rem;
        }}
        
        .grade-header {{
            font-size: 0.875rem;
            color: #666666;
            text-transform: uppercase;
            letter-spacing: 1px;
            font-weight: 600;
            margin-bottom: 1.5rem;
        }}
        
        .grade-display-large {{
            display: flex;
            align-items: center;
            gap: 1.5rem;
            margin-bottom: 1.5rem;
        }}
        
        .grade-circle-large {{
            width: 100px;
            height: 100px;
            border-radius: 50%;
            border: 5px solid;
            display: flex;
            align-items: center;
            justify-content: center;
            flex-shrink: 0;
        }}
        
        .grade-letter-large {{
            font-size: 3rem;
            font-weight: 700;
        }}
        
        .grade-info {{
            flex: 1;
        }}
        
        .grade-score-large {{
            font-size: 2.5rem;
            font-weight: 700;
            color: #000000;
            line-height: 1;
        }}
        
        .grade-max {{
            font-size: 1.5rem;
            color: #666666;
        }}
        
        .grade-label-large {{
            font-size: 0.875rem;
            color: #666666;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-top: 0.5rem;
        }}
        
        .score-progress {{
            margin-top: 1rem;
        }}
        
        .score-progress-bar {{
            height: 12px;
            background: #e0e0e0;
            border-radius: 6px;
            overflow: hidden;
        }}
        
        .score-progress-fill {{
            height: 100%;
            transition: width 2s ease-out;
        }}
        
        .findings-grid {{
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 1.25rem;
        }}
        
        .finding-stat {{
            background: #ffffff;
            border: 2px solid #e0e0e0;
            border-radius: 8px;
            padding: 1.5rem;
            position: relative;
            cursor: pointer;
            transition: all 0.3s ease;
            overflow: hidden;
        }}
        
        .finding-stat:hover {{
            transform: translateY(-4px);
            box-shadow: 0 6px 16px rgba(0,0,0,0.1);
        }}
        
        .critical-stat:hover {{
            border-color: #d32f2f;
        }}
        
        .warning-stat:hover {{
            border-color: #f57c00;
        }}
        
        .notice-stat:hover {{
            border-color: #1976d2;
        }}
        
        .info-stat:hover {{
            border-color: #616161;
        }}
        
        .finding-number {{
            font-size: 3rem;
            font-weight: 700;
            color: #000000;
            line-height: 1;
            margin-bottom: 0.5rem;
        }}
        
        .finding-label {{
            font-size: 0.875rem;
            color: #666666;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            font-weight: 600;
        }}
        
        .finding-bar {{
            position: absolute;
            bottom: 0;
            left: 0;
            height: 4px;
            transition: width 1.5s ease-out;
        }}
        
        .app-info-prominent {{
            background: #f5f5f5;
            border: 2px solid #cccccc;
            border-radius: 8px;
            padding: 2rem;
            margin-bottom: 2rem;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
        }}
        
        .app-info-header {{
            margin-bottom: 1.5rem;
            padding-bottom: 1rem;
            border-bottom: 2px solid #d0d0d0;
        }}
        
        .app-info-header h3 {{
            margin: 0 0 0.5rem 0;
            font-size: 1.5rem;
            color: #2c2c2c;
            font-weight: 700;
        }}
        
        .app-info-header p {{
            margin: 0;
            color: #666666;
            font-size: 0.925rem;
        }}
        
        .info-table-prominent {{
            width: 100%;
            border-collapse: separate;
            border-spacing: 0;
        }}
        
        .info-table-prominent tbody tr {{
            border-bottom: 1px solid #e0e0e0;
        }}
        
        .info-table-prominent tbody tr:last-child {{
            border-bottom: none;
        }}
        
        .info-label {{
            padding: 1rem;
            font-weight: 700;
            color: #2c2c2c;
            background: #e8e8e8;
            width: 200px;
            font-size: 0.925rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            border-right: 2px solid #d0d0d0;
        }}
        
        .info-value {{
            padding: 1rem 1.25rem;
            color: #333333;
            font-size: 0.95rem;
            background: #ffffff;
        }}
        
        .package-name {{
            font-family: 'Courier New', monospace;
            background: #e0e0e0;
            padding: 0.35rem 0.75rem;
            border-radius: 4px;
            font-size: 0.9rem;
            color: #1a1a1a;
            border: 1px solid #c0c0c0;
            font-weight: 600;
        }}
        
        .findings-table-container {{
            margin-top: 1.5rem;
            overflow-x: auto;
        }}
        
        .findings-table {{
            width: 100%;
            border-collapse: collapse;
        }}
        
        .findings-table thead {{
            background: #000000;
            color: #ffffff;
        }}
        
        .findings-table th {{
            padding: 1rem;
            text-align: left;
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.875rem;
            letter-spacing: 0.5px;
        }}
        
        .findings-table td {{
            padding: 1rem;
            border-bottom: 1px solid #e0e0e0;
        }}
        
        .finding-row {{
            cursor: pointer;
            transition: background-color 0.2s;
        }}
        
        .finding-row:hover {{
            background-color: #fafafa;
        }}
        
        .details-row {{
            display: none;
            background: #f5f5f5;
        }}
        
        .details-row.active {{
            display: table-row;
        }}
        
        .severity-badge {{
            display: inline-block;
            padding: 0.4rem 0.8rem;
            border-radius: 3px;
            color: #ffffff;
            font-weight: 600;
            font-size: 0.875rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        
        .finding-summary {{
            font-weight: 600;
            color: #000000;
            margin-bottom: 0.5rem;
        }}
        
        .finding-meta {{
            display: flex;
            gap: 1rem;
            flex-wrap: wrap;
        }}
        
        .meta-item {{
            font-size: 0.875rem;
            color: #666666;
        }}
        
        .expand-cell {{
            text-align: center;
            width: 40px;
        }}
        
        .expand-icon {{
            display: inline-block;
            transition: transform 0.3s;
            font-size: 1rem;
        }}
        
        .expand-icon.rotated {{
            transform: rotate(-90deg);
        }}
        
        .finding-details {{
            padding: 1.5rem;
            background: #ffffff;
            border: 1px solid #e0e0e0;
            border-radius: 4px;
        }}
        
        .detail-section {{
            margin-bottom: 1.5rem;
        }}
        
        .detail-section:last-child {{
            margin-bottom: 0;
        }}
        
        .detail-section h4 {{
            color: #000000;
            font-weight: 600;
            margin-bottom: 0.75rem;
            font-size: 1rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        
        .detail-section p {{
            color: #424242;
            line-height: 1.6;
        }}
        
        .code-block {{
            background: #000000;
            color: #00ff00;
            padding: 1rem;
            border-radius: 4px;
            overflow-x: auto;
            font-family: 'Courier New', monospace;
            font-size: 0.875rem;
            max-height: 300px;
            overflow-y: auto;
            border: 1px solid #333333;
        }}
        
        code {{
            font-family: 'Courier New', monospace;
            background: #f5f5f5;
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 0.9em;
            color: #000000;
        }}
        
        .no-findings {{
            text-align: center;
            padding: 2rem;
            color: #2e7d32;
            font-size: 1.1rem;
            background: #c8e6c9;
            border-radius: 4px;
            border: 1px solid #81c784;
        }}
        
        .chart-container {{
            position: relative;
            height: 350px;
            margin-top: 1.5rem;
        }}
        
        .charts-grid {{
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 2rem;
        }}
        
        .chart-card {{
            background: #ffffff;
            border: 1px solid #e0e0e0;
            border-radius: 8px;
            padding: 1.5rem;
        }}
        
        .chart-header {{
            margin-bottom: 1rem;
            border-bottom: 2px solid #f0f0f0;
            padding-bottom: 0.75rem;
        }}
        
        .chart-header h3 {{
            font-size: 1.125rem;
            font-weight: 600;
            color: #000000;
            margin: 0 0 0.25rem 0;
        }}
        
        .chart-header p {{
            font-size: 0.875rem;
            color: #666666;
            margin: 0;
        }}
        
        .footer {{
            text-align: center;
            padding: 2rem;
            background: #f5f5f5;
            border-top: 1px solid #e0e0e0;
            margin-top: 2rem;
        }}
        
        .footer p {{
            color: #666666;
            font-size: 0.875rem;
        }}
        
        @media (max-width: 768px) {{
            .grade-section {{ grid-template-columns: 1fr; }}
            .findings-grid {{ grid-template-columns: 1fr; }}
            .charts-grid {{ grid-template-columns: 1fr; }}
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Matrisks Dynamic Security Analysis Report</h1>
        <p class="subtitle">{self._escape_html(app_info.get('package_name', 'Application Security Assessment'))}</p>
        <p class="report-meta">Generated: {report_info.get('timestamp', '')} | Version: {report_info.get('analyzer_version', '1.0')}</p>
    </div>
    
    <div class="container">
        <!-- Executive Summary -->
        <div class="section">
            <div class="executive-summary">
                <div class="summary-header">
                    <div class="header-content">
                        <h1 class="app-name">{self._escape_html(app_info.get('package_name', 'N/A'))}</h1>
                        <div class="version-info">Analysis Duration: {app_info.get('analysis_duration', 'N/A')}</div>
                    </div>
                    <div class="risk-status {risk_class}">
                        <div class="risk-badge-large">{risk_level}</div>
                        <div class="risk-description">{risk_message}</div>
                    </div>
                </div>
                
                <div class="summary-main">
                    <div class="grade-section">
                        <div class="grade-card">
                            <div class="grade-header">Security Assessment</div>
                            <div class="grade-display-large">
                                <div class="grade-circle-large" style="border-color: {grade_color}">
                                    <span class="grade-letter-large" style="color: {grade_color}">{security['security_grade']}</span>
                                </div>
                                <div class="grade-info">
                                    <div class="grade-score-large">{security['security_score']}<span class="grade-max">/100</span></div>
                                    <div class="grade-label-large">Security Score</div>
                                </div>
                            </div>
                            <div class="score-progress">
                                <div class="score-progress-bar">
                                    <div class="score-progress-fill" style="width: {security['security_score']}%; background: {grade_color}"></div>
                                </div>
                            </div>
                        </div>
                        
                        <div class="findings-grid">
                            <div class="finding-stat critical-stat">
                                <div class="finding-number">{critical_count}</div>
                                <div class="finding-label">Critical</div>
                                <div class="finding-bar" style="width: {critical_pct}%; background: #d32f2f"></div>
                            </div>
                            
                            <div class="finding-stat warning-stat">
                                <div class="finding-number">{high_count}</div>
                                <div class="finding-label">High</div>
                                <div class="finding-bar" style="width: {high_pct}%; background: #f57c00"></div>
                            </div>
                            
                            <div class="finding-stat notice-stat">
                                <div class="finding-number">{medium_count}</div>
                                <div class="finding-label">Medium</div>
                                <div class="finding-bar" style="width: {medium_pct}%; background: #1976d2"></div>
                            </div>
                            
                            <div class="finding-stat info-stat">
                                <div class="finding-number">{low_count}</div>
                                <div class="finding-label">Low</div>
                                <div class="finding-bar" style="width: {low_pct}%; background: #616161"></div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Application Information -->
        <div class="section">
            <h2>Application Information</h2>
            <div class="app-info-prominent">
                <div class="app-info-header">
                    <h3>Runtime Analysis Details</h3>
                    <p>Information captured during dynamic analysis execution</p>
                </div>
                <table class="info-table-prominent">
                    <tbody>
                        <tr>
                            <td class="info-label">Package Name</td>
                            <td class="info-value"><code class="package-name">{self._escape_html(app_info.get('package_name', 'N/A'))}</code></td>
                        </tr>
                        <tr>
                            <td class="info-label">Analysis Date</td>
                            <td class="info-value">{app_info.get('analysis_timestamp', 'N/A')}</td>
                        </tr>
                        <tr>
                            <td class="info-label">Analysis Duration</td>
                            <td class="info-value">{app_info.get('analysis_duration', 'N/A')}</td>
                        </tr>
                        <tr>
                            <td class="info-label">Total API Calls</td>
                            <td class="info-value">{report_data['api_analysis']['total_api_calls']}</td>
                        </tr>
                        <tr>
                            <td class="info-label">Network Requests</td>
                            <td class="info-value">{len(report_data.get('network_analysis', {}).get('tcp_connections', []))} TCP/UDP, {len(report_data.get('network_analysis', {}).get('https_requests', []))} HTTPS</td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>
        
        <!-- Security Charts -->
        <div class="section">
            <h2>Security Analysis Overview</h2>
            <p class="section-description">Interactive visualizations of runtime behavior and security findings</p>
            
            <div class="charts-grid">
                <div class="chart-card">
                    <div class="chart-header">
                        <h3>API Call Distribution</h3>
                        <p>Breakdown of API calls by category</p>
                    </div>
                    <div class="chart-container">
                        <canvas id="apiChart"></canvas>
                    </div>
                </div>
                
                <div class="chart-card">
                    <div class="chart-header">
                        <h3>Risk Distribution</h3>
                        <p>Findings grouped by severity level</p>
                    </div>
                    <div class="chart-container">
                        <canvas id="riskChart"></canvas>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- API Findings -->
        <div class="section">
            <h2>API Call Analysis</h2>
            <p class="section-description">Detailed breakdown of all intercepted API calls during runtime</p>
            {api_findings_html}
        </div>
        
        <!-- Network Findings -->
        <div class="section">
            <h2>Network Activity</h2>
            <p class="section-description">All network connections and HTTPS requests captured during analysis</p>
            {network_findings_html}
        </div>
        
        <!-- File Operations -->
        <div class="section">
            <h2>File System Operations</h2>
            <p class="section-description">File access and storage operations detected</p>
            {file_findings_html}
        </div>
        
        <!-- System Events -->
        <div class="section">
            <h2>System Events</h2>
            <p class="section-description">Critical system events from logcat monitoring</p>
            {system_findings_html}
        </div>
        
        <div class="footer">
            <p><strong>Generated by Matrisks Dynamic Analyzer v1.0</strong></p>
            <p>Real-time Android Security Analysis Platform</p>
        </div>
    </div>
    
    <script>
        // Prepare data for charts
        const apiData = {json.dumps(report_data['api_analysis']['by_category'])};
        const riskData = {{
            'Critical': {critical_count},
            'High': {high_count},
            'Medium': {medium_count},
            'Low': {low_count},
            'Info': {info_count}
        }};
        
        // API Distribution Chart
        const apiCtx = document.getElementById('apiChart').getContext('2d');
        new Chart(apiCtx, {{
            type: 'doughnut',
            data: {{
                labels: Object.keys(apiData),
                datasets: [{{
                    data: Object.values(apiData),
                    backgroundColor: ['#000000', '#2c2c2c', '#424242', '#616161', '#9e9e9e'],
                    borderWidth: 2,
                    borderColor: '#ffffff'
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{
                    legend: {{
                        position: 'bottom',
                        labels: {{
                            padding: 15,
                            font: {{ size: 12 }},
                            color: '#000000'
                        }}
                    }}
                }}
            }}
        }});
        
        // Risk Distribution Chart
        const riskCtx = document.getElementById('riskChart').getContext('2d');
        new Chart(riskCtx, {{
            type: 'bar',
            data: {{
                labels: Object.keys(riskData),
                datasets: [{{
                    label: 'Findings',
                    data: Object.values(riskData),
                    backgroundColor: ['#d32f2f', '#f57c00', '#1976d2', '#616161', '#9e9e9e'],
                    borderWidth: 0
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{
                    legend: {{ display: false }}
                }},
                scales: {{
                    y: {{
                        beginAtZero: true,
                        ticks: {{ stepSize: 1, color: '#000000' }},
                        grid: {{ color: '#e0e0e0' }}
                    }},
                    x: {{
                        ticks: {{ color: '#000000' }},
                        grid: {{ display: false }}
                    }}
                }}
            }}
        }});
        
        // Toggle finding details
        function toggleDetails(rowId) {{
            const detailsRow = document.getElementById('details-' + rowId);
            const icon = document.getElementById('icon-' + rowId);
            
            if (detailsRow && icon) {{
                if (detailsRow.classList.contains('active')) {{
                    detailsRow.classList.remove('active');
                    icon.classList.remove('rotated');
                }} else {{
                    detailsRow.classList.add('active');
                    icon.classList.add('rotated');
                }}
            }}
        }}
    </script>
</body>
</html>
"""
        
        return html

    def save_html_report(self, output_path: str = None) -> str:
        """Save HTML report"""
        if output_path is None:
            output_path = self.analysis_dir / 'comprehensive_report.html'
        else:
            output_path = Path(output_path)
        
        html_content = self.generate_html_report()
        
        # Ensure directory exists
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"✓ HTML report saved: {output_path}")
        return str(output_path)
    
    def save_all_reports(self) -> Dict[str, str]:
        """
        Save all report formats (JSON, CSV, HTML)
        
        Returns:
            Dictionary mapping format to output path
        """
        report_paths = {}
        
        print(f"\n📊 Generating comprehensive reports for: {self.analysis_name}")
        print("=" * 60)
        
        # JSON report
        json_path = self.save_json_report()
        report_paths['json'] = json_path
        
        # CSV report
        csv_path = self.save_csv_report()
        report_paths['csv'] = csv_path
        
        # HTML report
        html_path = self.save_html_report()
        report_paths['html'] = html_path
        
        print("=" * 60)
        print(f"✅ All reports generated successfully!")
        print(f"📁 Location: {self.analysis_dir}")
        
        return report_paths


def generate_reports_for_analysis(analysis_dir: str) -> Dict[str, str]:
    """
    Convenience function to generate all reports for an analysis directory
    
    Args:
        analysis_dir: Path to analysis results directory
    
    Returns:
        Dictionary of report paths
    """
    generator = DynamicReportGenerator(analysis_dir)
    return generator.save_all_reports()


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        analysis_dir = sys.argv[1]
        if os.path.exists(analysis_dir):
            print(f"Generating reports for: {analysis_dir}")
            generate_reports_for_analysis(analysis_dir)
        else:
            print(f"Error: Directory not found: {analysis_dir}")
            sys.exit(1)
    else:
        print("Usage: python report_generator.py <analysis_directory>")
        print("Example: python report_generator.py scanned_results/analysis_MyApp_20231115_120000")
