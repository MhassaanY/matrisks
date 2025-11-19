"""
Matrisks Advanced Report Generator v2.0
Comprehensive reporting system similar to MobSF structure
Generates JSON, HTML, CSV, PDF reports with complete scan data
"""

import json
import csv
import os
import hashlib
from datetime import datetime
from typing import Dict, List, Any, Optional
from collections import defaultdict, Counter
from security_mappings import enrich_finding_with_classifications


class MatrisksReportGeneratorV2:
    """
    Enhanced report generator with MobSF-like comprehensive structure
    """
    
    def __init__(self, scan_data: Dict[str, Any], apk_info: Dict[str, Any], 
                 vector_results: Dict[str, Any], decompile_info: Dict[str, Any] = None):
        """
        Initialize report generator with all scan data
        
        Args:
            scan_data: Core scan metadata and timing information
            apk_info: APK information from androguard
            vector_results: All security vector findings
            decompile_info: Decompilation and code analysis info
        """
        self.scan_data = scan_data
        self.apk_info = apk_info
        self.vector_results = vector_results
        self.decompile_info = decompile_info or {}
        
        # Calculate security score
        self.security_score = self._calculate_security_score()
        self.security_grade = self._get_security_grade(self.security_score)
        
    def _calculate_security_score(self) -> int:
        """Calculate overall security score (0-100, higher is better)"""
        severity_weights = {
            'Critical': 20,
            'Warning': 10,
            'Notice': 5,
            'Info': 0
        }
        
        total_deductions = 0
        max_possible_deductions = 100
        
        for finding_id, finding in self.vector_results.items():
            severity = finding.get('level', 'Info')
            deduction = severity_weights.get(severity, 0)
            total_deductions += deduction
        
        # Cap deductions at 100
        total_deductions = min(total_deductions, max_possible_deductions)
        
        score = max(0, 100 - total_deductions)
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
    
    def _categorize_findings(self) -> Dict[str, List[Dict]]:
        """Categorize findings by security domain"""
        categories = defaultdict(list)
        
        category_mapping = {
            'webview': 'Web Security',
            'intent': 'Component Security',
            'crypto': 'Cryptography',
            'debug': 'Debug and Development',
            'storage': 'Storage and Backup',
            'backup': 'Storage and Backup',
            'adb': 'Storage and Backup',
            'sqlite': 'Database Security',
            'taint_analysis': 'Data Flow Analysis',
            'permissions': 'Permissions',
            'ssl': 'Network Security',
            'http': 'Network Security',
            'insecure_component': 'Component Security',
            'hardcoded_secrets': 'Code Security',
            'native': 'Native Code',
            'obfuscation': 'Code Protection',
            'external_storage': 'Storage and Backup'
        }
        
        for finding_id, finding in self.vector_results.items():
            # Enrich with CWE and OWASP mappings
            enriched_finding = enrich_finding_with_classifications(finding_id, finding)
            
            vector_name = (enriched_finding.get('vector_name') or '').lower()
            
            # Find matching category
            category = 'Other'
            for key, cat in category_mapping.items():
                if key in vector_name:
                    category = cat
                    break
            
            categories[category].append({
                'id': finding_id,
                **enriched_finding
            })
        
        return dict(categories)
    
    def _get_enriched_findings(self) -> Dict[str, Dict]:
        """Get all findings enriched with CWE and OWASP classifications"""
        enriched = {}
        for finding_id, finding in self.vector_results.items():
            enriched[finding_id] = enrich_finding_with_classifications(finding_id, finding)
        return enriched
    
    def _get_app_info_section(self) -> Dict[str, Any]:
        """Generate comprehensive app info section"""
        return {
            'app_name': self.apk_info.get('app_name', 'N/A'),
            'package_name': self.scan_data.get('package_name', 'N/A'),
            'version_name': self.scan_data.get('package_version_name', 'N/A'),
            'version_code': self.scan_data.get('package_version_code', 'N/A'),
            'min_sdk': self.scan_data.get('minSdk', 'N/A'),
            'target_sdk': self.scan_data.get('targetSdk', 'N/A'),
            'platform': self.scan_data.get('platform', 'Android'),
            'file_size_mb': self.scan_data.get('apk_file_size', 0),
            'md5': self.scan_data.get('file_md5', ''),
            'sha1': self.scan_data.get('file_sha1', ''),
            'sha256': self.scan_data.get('file_sha256', ''),
            'sha512': self.scan_data.get('file_sha512', ''),
        }
    
    def _get_security_analysis_section(self) -> Dict[str, Any]:
        """Generate security analysis section"""
        # Count findings by severity
        severity_counts = Counter()
        for finding in self.vector_results.values():
            severity = finding.get('level', 'Info')
            severity_counts[severity] += 1
        
        # Categorize findings
        categorized = self._categorize_findings()
        
        return {
            'security_score': self.security_score,
            'security_grade': self.security_grade,
            'total_issues': len(self.vector_results),
            'severity_distribution': dict(severity_counts),
            'category_distribution': {
                cat: len(findings) for cat, findings in categorized.items()
            },
            'high_risk_count': severity_counts.get('Critical', 0),
            'medium_risk_count': severity_counts.get('Warning', 0),
            'low_risk_count': severity_counts.get('Notice', 0),
            'info_count': severity_counts.get('Info', 0),
        }
    
    def _get_manifest_analysis(self) -> Dict[str, Any]:
        """Extract manifest analysis details"""
        manifest_findings = {}
        
        for finding_id, finding in self.vector_results.items():
            if 'manifest' in (finding.get('vector_name') or '').lower() or \
               finding_id in ['DEBUGGABLE', 'ALLOW_BACKUP', 'APP_OVERVIEW_SUMMARY']:
                manifest_findings[finding_id] = finding
        
        # Extract permissions
        permissions = []
        for finding_id, finding in self.vector_results.items():
            if finding_id == 'APP_OVERVIEW_SUMMARY':
                details = finding.get('details', '')
                if '--- Declared Permissions ---' in details:
                    perm_section = details.split('--- Declared Permissions ---')[1]
                    if '---' in perm_section:
                        perm_section = perm_section.split('---')[0]
                    permissions = [line.strip('- ').strip() for line in perm_section.split('\n') 
                                 if line.strip().startswith('-')]
        
        return {
            'debuggable': any('DEBUGGABLE' in fid for fid in manifest_findings.keys()),
            'allow_backup': any('ALLOW_BACKUP' in fid for fid in manifest_findings.keys()),
            'permissions': permissions,
            'permission_count': len(permissions),
            'findings': manifest_findings
        }
    
    def _get_code_analysis(self) -> Dict[str, Any]:
        """Get code analysis section"""
        code_findings = {}
        
        code_vectors = [
            'crypto', 'webview', 'sqlite', 'taint', 
            'hardcoded', 'dynamic_code', 'native'
        ]
        
        for finding_id, finding in self.vector_results.items():
            vector_name = (finding.get('vector_name') or '').lower()
            if any(cv in vector_name for cv in code_vectors):
                code_findings[finding_id] = finding
        
        return {
            'total_code_issues': len(code_findings),
            'findings': code_findings,
            'decompilation_info': self.decompile_info
        }
    
    def _get_network_security(self) -> Dict[str, Any]:
        """Get network security analysis"""
        network_findings = {}
        
        for finding_id, finding in self.vector_results.items():
            vector_name = (finding.get('vector_name') or '').lower()
            if any(nv in vector_name for nv in ['ssl', 'http', 'network', 'url']):
                network_findings[finding_id] = finding
        
        return {
            'total_network_issues': len(network_findings),
            'findings': network_findings
        }
    
    def _get_component_analysis(self) -> Dict[str, Any]:
        """Get component security analysis"""
        component_findings = {}
        
        for finding_id, finding in self.vector_results.items():
            if 'component' in (finding.get('vector_name') or '').lower() or \
               'EXPORTED' in finding_id or 'ACTIVITY' in finding_id or \
               'SERVICE' in finding_id or 'RECEIVER' in finding_id:
                component_findings[finding_id] = finding
        
        return {
            'total_component_issues': len(component_findings),
            'findings': component_findings
        }
    
    def _get_storage_analysis(self) -> Dict[str, Any]:
        """Get storage security analysis"""
        storage_findings = {}
        
        for finding_id, finding in self.vector_results.items():
            vector_name = (finding.get('vector_name') or '').lower()
            if any(sv in vector_name for sv in ['storage', 'backup', 'adb', 'sqlite']):
                storage_findings[finding_id] = finding
        
        return {
            'total_storage_issues': len(storage_findings),
            'findings': storage_findings
        }
    
    def _get_owasp_masvs_mapping(self) -> Dict[str, List[str]]:
        """Map findings to OWASP MASVS categories"""
        masvs_mapping = defaultdict(list)
        
        # OWASP MASVS categories
        categories = {
            'MSTG-STORAGE': ['storage', 'backup', 'external_storage', 'sqlite'],
            'MSTG-CRYPTO': ['crypto', 'encryption'],
            'MSTG-AUTH': ['authentication', 'access_control'],
            'MSTG-NETWORK': ['ssl', 'http', 'network'],
            'MSTG-PLATFORM': ['webview', 'intent', 'component'],
            'MSTG-CODE': ['obfuscation', 'debug', 'hardcoded', 'dynamic_code'],
            'MSTG-RESILIENCE': ['root', 'tamper', 'reverse']
        }
        
        for finding_id, finding in self.vector_results.items():
            vector_name = (finding.get('vector_name') or '').lower()

            for masvs_cat, keywords in categories.items():
                if any(kw in vector_name for kw in keywords):
                    masvs_mapping[masvs_cat].append(finding_id)
                    break
        
        return dict(masvs_mapping)
    
    def generate_json_report(self) -> Dict[str, Any]:
        """
        Generate comprehensive JSON report with MobSF-like structure
        """
        report = {
            'report_info': {
                'generated_by': 'Matrisks Framework v2.0.0',
                'generated_at': datetime.utcnow().isoformat() + 'Z',
                'report_version': '2.0',
                'scan_id': self.scan_data.get('signature_unique_analyze', ''),
                'scan_type': 'static_analysis',
                'analyzer_engine': self.scan_data.get('analyze_engine_build', 1)
            },
            
            'app_info': self._get_app_info_section(),
            
            'security_analysis': self._get_security_analysis_section(),
            
            'manifest_analysis': self._get_manifest_analysis(),
            
            'code_analysis': self._get_code_analysis(),
            
            'network_security': self._get_network_security(),
            
            'component_security': self._get_component_analysis(),
            
            'storage_security': self._get_storage_analysis(),
            
            'findings': {
                'total_count': len(self.vector_results),
                'categorized': self._categorize_findings(),
                'all_findings': self._get_enriched_findings()
            },
            
            'compliance': {
                'owasp_masvs': self._get_owasp_masvs_mapping()
            },
            
            'performance_metrics': {
                'total_scan_time_seconds': self.scan_data.get('time_total', 0),
                'analysis_time_seconds': self.scan_data.get('time_analyze', 0),
                'decompilation_time_seconds': self.scan_data.get('time_loading_vm', 0),
                'scan_started': self.scan_data.get('time_starting_analyze', ''),
                'scan_finished': self.scan_data.get('time_finish_analyze', '')
            },
            
            'file_hashes': {
                'md5': self.scan_data.get('file_md5', ''),
                'sha1': self.scan_data.get('file_sha1', ''),
                'sha256': self.scan_data.get('file_sha256', ''),
                'sha512': self.scan_data.get('file_sha512', '')
            },
            
            'metadata': {
                'apk_path': self.scan_data.get('apk_filepath_absolute', ''),
                'file_size_mb': self.scan_data.get('apk_file_size', 0),
                'platform': self.scan_data.get('platform', 'Android'),
                'analyze_mode': self.scan_data.get('analyze_mode', 'single'),
                'analyze_status': self.scan_data.get('analyze_status', 'unknown')
            }
        }
        
        return report
    
    def save_json_report(self, output_path: str) -> None:
        """Save JSON report to file"""
        from datetime import datetime, date
        
        def json_serial(obj):
            """JSON serializer for objects not serializable by default"""
            if isinstance(obj, (datetime, date)):
                return obj.isoformat()
            raise TypeError(f"Type {type(obj)} not serializable")
        
        report = self.generate_json_report()
        
        # Ensure directory exists
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False, default=json_serial)
        
        print(f"✓ Comprehensive JSON report saved: {output_path}")
    
    def generate_csv_report(self) -> List[List[str]]:
        """Generate comprehensive CSV with all finding details"""
        csv_data = []
        
        # Header row with all fields
        headers = [
            'Finding ID',
            'Severity',
            'Risk',
            'Confidence',
            'Category',
            'Vector',
            'Title',
            'Summary',
            'Description',
            'Details',
            'Suggestion',
            'CWE',
            'OWASP Mobile',
            'Code Location',
            'File',
            'Class',
            'Method'
        ]
        csv_data.append(headers)
        
        # Get enriched findings with CWE/OWASP mappings
        enriched_findings = self._get_enriched_findings()
        
        # Add each finding as a row
        for finding_id, finding in enriched_findings.items():
            # Extract code location if available
            details = finding.get('details', '')
            code_location = ''
            file_name = ''
            class_name = ''
            method_name = ''
            
            if 'Location:' in details:
                code_location = details.split('Location:')[1].split('\n')[0].strip() if 'Location:' in details else ''
                
                # Parse location for class and method
                if ';->' in code_location:
                    parts = code_location.split(';->')
                    class_name = parts[0].replace('L', '').replace('/', '.')
                    method_name = parts[1] if len(parts) > 1 else ''
            
            row = [
                finding_id,
                finding.get('level', 'Info'),
                finding.get('risk', 'N/A'),
                str(finding.get('confidence', 'N/A')),
                ', '.join(finding.get('special_tag', [])) if finding.get('special_tag') else 'N/A',
                finding.get('vector_name', 'N/A'),
                finding.get('title', '').replace('\n', ' ')[:500],  # Limit length
                finding.get('summary', 'N/A'),
                finding.get('description', 'N/A'),
                details[:1000],  # Limit details length
                finding.get('suggestion', 'N/A')[:500],
                finding.get('cwe', 'N/A'),
                finding.get('owasp_mobile', 'N/A'),
                code_location,
                file_name,
                class_name,
                method_name
            ]
            csv_data.append(row)
        
        return csv_data
    
    def save_csv_report(self, output_path: str) -> None:
        """Save comprehensive CSV report"""
        csv_data = self.generate_csv_report()
        
        # Ensure directory exists
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f, quoting=csv.QUOTE_ALL)
            writer.writerows(csv_data)
        
        print(f"✓ Comprehensive CSV report saved: {output_path}")
    
    def generate_html_report(self) -> str:
        """Generate comprehensive HTML report"""
        import html_report_generator
        
        report_data = self.generate_json_report()
        html_content = html_report_generator.generate_html_dashboard(report_data)
        
        return html_content
    
    def save_html_report(self, output_path: str) -> None:
        """Save HTML report to file"""
        html_content = self.generate_html_report()
        
        # Ensure directory exists
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"✓ Comprehensive HTML dashboard saved: {output_path}")
    
    def save_all_reports(self, output_dir: str, base_filename: str = 'report') -> Dict[str, str]:
        """
        Save all report formats
        
        Returns:
            Dictionary mapping format to output path
        """
        os.makedirs(output_dir, exist_ok=True)
        
        report_paths = {}
        
        # JSON report
        json_path = os.path.join(output_dir, f'{base_filename}.json')
        self.save_json_report(json_path)
        report_paths['json'] = json_path
        
        # CSV report
        csv_path = os.path.join(output_dir, f'{base_filename}.csv')
        self.save_csv_report(csv_path)
        report_paths['csv'] = csv_path
        
        # HTML report
        html_path = os.path.join(output_dir, f'{base_filename}.html')
        self.save_html_report(html_path)
        report_paths['html'] = html_path
        
        print(f"\n✓ All reports generated successfully in: {output_dir}")
        
        return report_paths


def create_report_from_scan(scan_data: Dict, apk_info: Dict, 
                           vector_results: Dict, output_dir: str) -> Dict[str, str]:
    """
    Convenience function to create all reports from scan data
    
    Args:
        scan_data: Core scan metadata
        apk_info: APK information
        vector_results: Security findings
        output_dir: Output directory for reports
    
    Returns:
        Dictionary of report paths
    """
    generator = MatrisksReportGeneratorV2(scan_data, apk_info, vector_results)
    return generator.save_all_reports(output_dir)
