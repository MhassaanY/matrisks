"""
Matrisks Professional HTML Report Generator
Clean black/white design with color-coded vulnerabilities
No emojis - Professional security report
"""

from typing import Dict, Any, List
import json
from collections import Counter


def escape_html(text: str) -> str:
    """Escape HTML special characters"""
    if not isinstance(text, str):
        text = str(text)
    return (text
            .replace('&', '&amp;')
            .replace('<', '&lt;')
            .replace('>', '&gt;')
            .replace('"', '&quot;')
            .replace("'", '&#39;'))


def get_severity_color(severity: str) -> str:
    """Get color for severity level"""
    colors = {
        'Critical': '#d32f2f',  # Red
        'Warning': '#f57c00',   # Orange
        'Notice': '#1976d2',    # Blue
        'Info': '#616161'       # Gray
    }
    return colors.get(severity, '#616161')


def get_grade_color(grade: str) -> str:
    """Get color for security grade"""
    colors = {
        'A': '#2e7d32',  # Green
        'B': '#558b2f',  # Light green
        'C': '#f57c00',  # Orange
        'D': '#e64a19',  # Deep orange
        'F': '#c62828'   # Deep red
    }
    return colors.get(grade, '#616161')


def generate_executive_summary(report_data: Dict[str, Any]) -> str:
    """Generate interactive executive summary section"""
    security = report_data['security_analysis']
    app_info = report_data['app_info']
    
    grade_color = get_grade_color(security['security_grade'])
    
    # Calculate percentages for progress bars
    total = security['total_issues']
    critical_pct = (security['high_risk_count'] * 100 // total) if total > 0 else 0
    warning_pct = (security['medium_risk_count'] * 100 // total) if total > 0 else 0
    notice_pct = (security['low_risk_count'] * 100 // total) if total > 0 else 0
    info_pct = (security['info_count'] * 100 // total) if total > 0 else 0
    
    # Determine risk level
    if security['high_risk_count'] > 0:
        risk_level = "HIGH RISK"
        risk_class = "risk-high"
        risk_message = "Critical vulnerabilities detected. Immediate remediation required."
    elif security['medium_risk_count'] > 3:
        risk_level = "MEDIUM RISK"
        risk_class = "risk-medium"
        risk_message = "Multiple warnings found. Review and address soon."
    elif security['medium_risk_count'] > 0:
        risk_level = "LOW-MEDIUM RISK"
        risk_class = "risk-low-medium"
        risk_message = "Some security concerns identified. Review recommended."
    else:
        risk_level = "LOW RISK"
        risk_class = "risk-low"
        risk_message = "No critical issues detected. Continue monitoring."
    
    summary_html = f"""
    <div class="executive-summary">
        <div class="summary-header">
            <div class="header-content">
                <h1 class="app-name">{escape_html(str(app_info.get('package_name', 'Application Security Report')))}</h1>
                <div class="version-info">Version {escape_html(str(app_info.get('version_name', 'N/A')))} (Code: {app_info.get('version_code', 'N/A')})</div>
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
                    <div class="finding-stat critical-stat" onclick="scrollToSection('Critical')">
                        <div class="finding-number animate-count" data-target="{security['high_risk_count']}">{security['high_risk_count']}</div>
                        <div class="finding-label">Critical</div>
                        <div class="finding-bar" style="width: {critical_pct}%; background: #d32f2f"></div>
                    </div>
                    
                    <div class="finding-stat warning-stat" onclick="scrollToSection('Warning')">
                        <div class="finding-number animate-count" data-target="{security['medium_risk_count']}">{security['medium_risk_count']}</div>
                        <div class="finding-label">Warning</div>
                        <div class="finding-bar" style="width: {warning_pct}%; background: #f57c00"></div>
                    </div>
                    
                    <div class="finding-stat notice-stat" onclick="scrollToSection('Notice')">
                        <div class="finding-number animate-count" data-target="{security['low_risk_count']}">{security['low_risk_count']}</div>
                        <div class="finding-label">Notice</div>
                        <div class="finding-bar" style="width: {notice_pct}%; background: #1976d2"></div>
                    </div>
                    
                    <div class="finding-stat info-stat" onclick="scrollToSection('Info')">
                        <div class="finding-number animate-count" data-target="{security['info_count']}">{security['info_count']}</div>
                        <div class="finding-label">Info</div>
                        <div class="finding-bar" style="width: {info_pct}%; background: #616161"></div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    """
    
    return summary_html


def generate_app_info_section(app_info: Dict[str, Any]) -> str:
    """Generate application information section"""
    info_html = f"""
    <div class="app-info-prominent">
        <div class="app-info-header">
            <h3>Application Details</h3>
            <p>Core information about the analyzed application</p>
        </div>
        <table class="info-table-prominent">
            <tbody>
                <tr>
                    <td class="info-label">Package Name</td>
                    <td class="info-value"><code class="package-name">{escape_html(str(app_info.get('package_name', 'N/A')))}</code></td>
                </tr>
                <tr>
                    <td class="info-label">Version</td>
                    <td class="info-value">
                        <span class="version-badge">{escape_html(str(app_info.get('version_name', 'N/A')))}</span>
                        <span class="version-code">Code: {app_info.get('version_code', 'N/A')}</span>
                    </td>
                </tr>
                <tr>
                    <td class="info-label">SDK Levels</td>
                    <td class="info-value">
                        <div class="sdk-info">
                            <span class="sdk-badge sdk-min">Min: API {app_info.get('min_sdk', 'N/A')}</span>
                            <span class="sdk-badge sdk-target">Target: API {app_info.get('target_sdk', 'N/A')}</span>
                        </div>
                    </td>
                </tr>
                <tr>
                    <td class="info-label">File Size</td>
                    <td class="info-value"><span class="file-size">{app_info.get('file_size_mb', 0):.2f} MB</span></td>
                </tr>
                <tr class="hash-row">
                    <td class="info-label">MD5</td>
                    <td class="info-value"><code class="hash hash-md5">{app_info.get('md5', 'N/A')}</code></td>
                </tr>
                <tr class="hash-row">
                    <td class="info-label">SHA-1</td>
                    <td class="info-value"><code class="hash hash-sha1">{app_info.get('sha1', 'N/A')}</code></td>
                </tr>
                <tr class="hash-row">
                    <td class="info-label">SHA-256</td>
                    <td class="info-value"><code class="hash hash-sha256">{app_info.get('sha256', 'N/A')}</code></td>
                </tr>
            </tbody>
        </table>
    </div>
    """
    return info_html


def generate_findings_table(findings: Dict[str, Dict], category: str = "Findings") -> str:
    """Generate detailed findings table with expandable rows"""
    if not findings:
        return f"<p class='no-findings'>No {category.lower()} detected in this application.</p>"
    
    # Sort by severity
    severity_order = {'Critical': 0, 'Warning': 1, 'Notice': 2, 'Info': 3}
    sorted_findings = sorted(findings.items(), 
                            key=lambda x: severity_order.get(x[1].get('level', 'Info'), 4))
    
    rows_html = ""
    for idx, (finding_id, finding) in enumerate(sorted_findings):
        severity = finding.get('level', 'Info')
        severity_color = get_severity_color(severity)
        
        title = finding.get('title', 'N/A')
        summary = finding.get('summary', 'N/A')
        details = finding.get('details', finding.get('vector_details', 'No additional details available'))
        suggestion = finding.get('suggestion', 'No specific recommendation available')
        risk = finding.get('risk', 'N/A')
        confidence = finding.get('confidence', 'N/A')
        vector = finding.get('vector_name', 'N/A').split('.')[-1]
        cwe = finding.get('cwe', 'N/A')
        owasp = finding.get('owasp_mobile', 'N/A')
        
        # Extract code location if available
        code_location = 'N/A'
        if 'Location:' in str(details):
            try:
                code_location = str(details).split('Location:')[1].split('\\n')[0].strip()
            except:
                pass
        
        unique_id = f"{category.replace(' ', '-')}-{idx}"
        
        rows_html += f"""
        <tr class="finding-row" onclick="toggleDetails('{unique_id}')">
            <td class="severity-cell">
                <span class="severity-badge" style="background-color: {severity_color}">{severity}</span>
            </td>
            <td class="summary-cell">
                <div class="finding-summary">{escape_html(summary)}</div>
                <div class="finding-meta">
                    <span class="meta-item">Vector: {escape_html(vector)}</span>
                    <span class="meta-item">Risk: {escape_html(str(risk))}</span>
                    <span class="meta-item">Confidence: {escape_html(str(confidence))}</span>
                </div>
            </td>
            <td class="classification-cell">
                <div class="classification-item">
                    <strong>CWE:</strong> {escape_html(str(cwe))}
                </div>
                <div class="classification-item">
                    <strong>OWASP:</strong> {escape_html(str(owasp))}
                </div>
            </td>
            <td class="expand-cell">
                <span class="expand-icon" id="icon-{unique_id}">▼</span>
            </td>
        </tr>
        <tr class="details-row" id="details-{unique_id}">
            <td colspan="4">
                <div class="finding-details">
                    <div class="detail-section">
                        <h4>Description</h4>
                        <p>{escape_html(title[:500])}</p>
                    </div>
                    
                    <div class="detail-section">
                        <h4>Technical Details</h4>
                        <pre class="code-block">{escape_html(str(details)[:2000])}</pre>
                    </div>
                    
                    {f'<div class="detail-section"><h4>Code Location</h4><code>{escape_html(code_location)}</code></div>' if code_location != 'N/A' else ''}
                    
                    <div class="detail-section">
                        <h4>Remediation</h4>
                        <p>{escape_html(str(suggestion))}</p>
                    </div>
                    
                    <div class="detail-section classification-details">
                        <h4>Security Classifications</h4>
                        <table class="classification-table">
                            <tr>
                                <td><strong>CWE Classification:</strong></td>
                                <td>{escape_html(str(cwe))}</td>
                            </tr>
                            <tr>
                                <td><strong>OWASP Mobile:</strong></td>
                                <td>{escape_html(str(owasp))}</td>
                            </tr>
                            <tr>
                                <td><strong>Risk Level:</strong></td>
                                <td>{escape_html(str(risk))}</td>
                            </tr>
                            <tr>
                                <td><strong>Confidence:</strong></td>
                                <td>{escape_html(str(confidence))}/5</td>
                            </tr>
                        </table>
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
                    <th class="severity-col">Severity</th>
                    <th class="summary-col">Finding</th>
                    <th class="classification-col">Classification</th>
                    <th class="expand-col"></th>
                </tr>
            </thead>
            <tbody>
                {rows_html}
            </tbody>
        </table>
    </div>
    """
    
    return table_html


def generate_manifest_analysis(manifest_data: Dict[str, Any]) -> str:
    """Generate manifest analysis section"""
    permissions = manifest_data.get('permissions', [])
    
    debuggable_status = "Yes" if manifest_data.get('debuggable') else "No"
    debuggable_class = "status-bad" if manifest_data.get('debuggable') else "status-good"
    
    backup_status = "Yes" if manifest_data.get('allow_backup') else "No"
    backup_class = "status-warning" if manifest_data.get('allow_backup') else "status-good"
    
    perms_html = ""
    if permissions:
        for perm in permissions:
            perms_html += f'<li class="permission-item"><code>{escape_html(perm)}</code></li>'
    else:
        perms_html = "<li>No permissions declared</li>"
    
    manifest_html = f"""
    <div class="manifest-section">
        <table class="info-table">
            <tr>
                <th>Configuration</th>
                <th>Status</th>
                <th>Security Impact</th>
            </tr>
            <tr>
                <td>Debuggable</td>
                <td><span class="status-badge {debuggable_class}">{debuggable_status}</span></td>
                <td>{"CRITICAL - Application can be debugged in production" if manifest_data.get('debuggable') else "Good - Debug mode is disabled"}</td>
            </tr>
            <tr>
                <td>Backup Allowed</td>
                <td><span class="status-badge {backup_class}">{backup_status}</span></td>
                <td>{"WARNING - Application data can be backed up via ADB" if manifest_data.get('allow_backup') else "Good - Backup is disabled"}</td>
            </tr>
            <tr>
                <td>Declared Permissions</td>
                <td>{manifest_data.get('permission_count', 0)}</td>
                <td>Review permissions for necessity</td>
            </tr>
        </table>
        
        <div class="permissions-section">
            <h3>Declared Permissions</h3>
            <ul class="permissions-list">
                {perms_html}
            </ul>
        </div>
    </div>
    """
    
    return manifest_html


def generate_charts_data(security_analysis: Dict[str, Any]) -> str:
    """Generate JavaScript data for charts"""
    severity_dist = security_analysis.get('severity_distribution', {})
    category_dist = security_analysis.get('category_distribution', {})
    
    # Prepare severity data with colors
    severity_labels = list(severity_dist.keys())
    severity_values = list(severity_dist.values())
    severity_colors = [get_severity_color(s) for s in severity_labels]
    
    # Get top 10 categories
    sorted_categories = sorted(category_dist.items(), key=lambda x: x[1], reverse=True)[:10]
    category_labels = [cat for cat, count in sorted_categories]
    category_counts = [count for cat, count in sorted_categories]
    
    # Generate gradient colors for categories
    category_colors = []
    for i in range(len(category_labels)):
        intensity = 255 - (i * 20)
        category_colors.append(f'rgb({intensity}, {intensity}, {intensity})')
    
    # Risk distribution over time (simulated for demo - you can add real data)
    risk_timeline = {
        'labels': ['Critical', 'Warning', 'Notice', 'Info'],
        'data': [severity_dist.get('Critical', 0), severity_dist.get('Warning', 0), 
                 severity_dist.get('Notice', 0), severity_dist.get('Info', 0)]
    }
    
    js_data = f"""
    const severityLabels = {json.dumps(severity_labels)};
    const severityValues = {json.dumps(severity_values)};
    const severityColors = {json.dumps(severity_colors)};
    const categoryLabels = {json.dumps(category_labels)};
    const categoryCounts = {json.dumps(category_counts)};
    const categoryColors = {json.dumps(category_colors)};
    const riskTimeline = {json.dumps(risk_timeline)};
    """
    
    return js_data


def generate_html_dashboard(report_data: Dict[str, Any]) -> str:
    """
    Generate complete professional HTML dashboard
    Clean black/white design with color-coded vulnerabilities
    """
    app_info = report_data.get('app_info', {})
    security_analysis = report_data.get('security_analysis', {})
    manifest_analysis = report_data.get('manifest_analysis', {})
    findings = report_data.get('findings', {})
    all_findings = findings.get('all_findings', {})
    categorized = findings.get('categorized', {})
    performance = report_data.get('performance_metrics', {})
    report_info = report_data.get('report_info', {})
    
    # Generate sections
    executive_summary = generate_executive_summary(report_data)
    app_info_html = generate_app_info_section(app_info)
    manifest_html = generate_manifest_analysis(manifest_analysis)
    
    # Generate categorized findings sections
    category_sections = ""
    for category, cat_findings in sorted(categorized.items()):
        cat_findings_dict = {f['id']: f for f in cat_findings}
        if cat_findings_dict:
            category_sections += f"""
            <div class="section">
                <h2>{category}</h2>
                <p class="section-description">Found {len(cat_findings_dict)} issue(s) in this category</p>
                {generate_findings_table(cat_findings_dict, category)}
            </div>
            """
    
    # Generate charts data
    charts_data = generate_charts_data(security_analysis)
    
    # Complete HTML template with professional black/white design
    html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Matrisks Security Analysis - {escape_html(str(app_info.get('package_name', 'Report')))}</title>
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
        
        .info-table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 1rem;
        }}
        
        .info-table th,
        .info-table td {{
            padding: 0.875rem;
            text-align: left;
            border-bottom: 1px solid #e0e0e0;
        }}
        
        .info-table th {{
            background: #f5f5f5;
            font-weight: 600;
            color: #000000;
            text-transform: uppercase;
            font-size: 0.875rem;
            letter-spacing: 0.5px;
        }}
        
        .info-table tr:hover {{
            background: #fafafa;
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
            width: 180px;
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
        
        .version-badge {{
            display: inline-block;
            background: #2c2c2c;
            color: #ffffff;
            padding: 0.4rem 0.9rem;
            border-radius: 4px;
            font-weight: 600;
            font-size: 0.875rem;
            margin-right: 0.5rem;
        }}
        
        .version-code {{
            color: #666666;
            font-size: 0.875rem;
            margin-left: 0.5rem;
        }}
        
        .sdk-info {{
            display: flex;
            gap: 0.75rem;
            align-items: center;
        }}
        
        .sdk-badge {{
            display: inline-block;
            padding: 0.4rem 0.9rem;
            border-radius: 4px;
            font-weight: 700;
            font-size: 0.875rem;
            border: 2px solid #d0d0d0;
            background: #ffffff;
            color: #2c2c2c;
        }}
        
        .sdk-badge.sdk-min {{
            background: #ffffff;
            color: #2c2c2c;
            border-color: #d0d0d0;
        }}
        
        .sdk-badge.sdk-target {{
            background: #ffffff;
            color: #2c2c2c;
            border-color: #d0d0d0;
        }}
        
        .file-size {{
            font-weight: 600;
            color: #2c2c2c;
        }}
        
        .hash-row .info-value {{
            font-family: 'Courier New', monospace;
            font-size: 0.85rem;
        }}
        
        .hash {{
            padding: 0.25rem 0.5rem;
            border-radius: 3px;
            display: inline-block;
            font-weight: 700;
            background: #ffffff;
            color: #2c2c2c;
            border: 1px solid #d0d0d0;
        }}
        
        .hash-md5 {{
            background: #ffffff;
            color: #2c2c2c;
            border: 1px solid #d0d0d0;
        }}
        
        .hash-sha1 {{
            background: #ffffff;
            color: #2c2c2c;
            border: 1px solid #d0d0d0;
        }}
        
        .hash-sha256 {{
            background: #ffffff;
            color: #2c2c2c;
            border: 1px solid #d0d0d0;
        }}
        
        code {{
            font-family: 'Courier New', monospace;
            background: #f5f5f5;
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 0.9em;
            color: #000000;
        }}
        
        .hash {{
            font-size: 0.75rem;
            word-break: break-all;
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
        
        .classification-cell {{
            font-size: 0.875rem;
        }}
        
        .classification-item {{
            margin-bottom: 0.25rem;
        }}
        
        .classification-item strong {{
            color: #000000;
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
        
        .classification-table {{
            width: 100%;
            border-collapse: collapse;
        }}
        
        .classification-table td {{
            padding: 0.5rem;
            border: 1px solid #e0e0e0;
        }}
        
        .classification-table td:first-child {{
            width: 180px;
            background: #f5f5f5;
        }}
        
        .status-badge {{
            display: inline-block;
            padding: 0.3rem 0.8rem;
            border-radius: 3px;
            font-weight: 600;
            font-size: 0.875rem;
        }}
        
        .status-good {{
            background: #c8e6c9;
            color: #1b5e20;
        }}
        
        .status-warning {{
            background: #ffe0b2;
            color: #e65100;
        }}
        
        .status-bad {{
            background: #ffcdd2;
            color: #b71c1c;
        }}
        
        .permissions-section {{
            margin-top: 1.5rem;
        }}
        
        .permissions-section h3 {{
            font-size: 1.125rem;
            margin-bottom: 1rem;
            color: #000000;
        }}
        
        .permissions-list {{
            list-style: none;
            background: #f5f5f5;
            border: 1px solid #e0e0e0;
            border-radius: 4px;
            padding: 1rem;
        }}
        
        .permission-item {{
            padding: 0.5rem;
            margin-bottom: 0.5rem;
            background: #ffffff;
            border-left: 3px solid #000000;
            border-radius: 3px;
        }}
        
        .permission-item:last-child {{
            margin-bottom: 0;
        }}
        
        .chart-container {{
            position: relative;
            height: 350px;
            margin-top: 1.5rem;
        }}
        
        .charts-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(450px, 1fr));
            gap: 2rem;
        }}
        
        .charts-grid-main {{
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 2rem;
            margin-bottom: 2rem;
        }}
        
        .charts-grid-secondary {{
            display: grid;
            grid-template-columns: 2fr 1fr;
            gap: 2rem;
        }}
        
        .chart-card {{
            background: #ffffff;
            border: 1px solid #e0e0e0;
            border-radius: 8px;
            padding: 1.5rem;
            transition: all 0.3s ease;
        }}
        
        .chart-card:hover {{
            box-shadow: 0 4px 12px rgba(0,0,0,0.08);
            transform: translateY(-2px);
        }}
        
        .chart-card-wide {{
            grid-column: span 1;
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
        
        .no-findings {{
            text-align: center;
            padding: 2rem;
            color: #2e7d32;
            font-size: 1.1rem;
            background: #c8e6c9;
            border-radius: 4px;
            border: 1px solid #81c784;
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
        
        .performance-stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-top: 1rem;
        }}
        
        .stat-box {{
            background: #f5f5f5;
            padding: 1rem;
            border: 1px solid #e0e0e0;
            border-radius: 4px;
        }}
        
        .stat-label {{
            font-size: 0.875rem;
            color: #666666;
            margin-bottom: 0.5rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        
        .stat-value {{
            font-size: 1.5rem;
            font-weight: 600;
            color: #000000;
        }}
        
        @media print {{
            .finding-row {{ cursor: default; }}
            .details-row {{ display: table-row !important; }}
            .expand-icon {{ display: none; }}
        }}
        
        @media (max-width: 768px) {{
            .header h1 {{ font-size: 1.5rem; }}
            .summary-hero {{
                flex-direction: column;
                text-align: center;
            }}
            .hero-left, .hero-right {{
                width: 100%;
            }}
            .summary-stats {{ grid-template-columns: 1fr; }}
            .charts-grid-main {{ grid-template-columns: 1fr; }}
            .charts-grid-secondary {{ grid-template-columns: 1fr; }}
            .charts-grid {{ grid-template-columns: 1fr; }}
            .chart-card-wide {{ grid-column: span 1; }}
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Matrisks Static Security Analysis Report</h1>
        <p class="subtitle">{escape_html(str(app_info.get('package_name', 'Application Security Assessment')))}</p>
        <p class="report-meta">Generated: {report_info.get('generated_at', '')} | Version: {report_info.get('report_version', '2.0')}</p>
    </div>
    
    <div class="container">
        <!-- Executive Summary -->
        <div class="section">
            {executive_summary}
        </div>
        
        <!-- Application Information -->
        <div class="section">
            <h2>Application Information</h2>
            {app_info_html}
        </div>
        
        <!-- Security Charts -->
        <div class="section">
            <h2>Security Analysis Overview</h2>
            <p class="section-description">Interactive visualizations of security findings and risk distribution</p>
            
            <div class="charts-grid-main">
                <div class="chart-card">
                    <div class="chart-header">
                        <h3>Severity Distribution</h3>
                        <p>Breakdown of findings by severity level</p>
                    </div>
                    <div class="chart-container">
                        <canvas id="severityChart"></canvas>
                    </div>
                </div>
                
                <div class="chart-card">
                    <div class="chart-header">
                        <h3>Risk Pyramid</h3>
                        <p>Visual hierarchy of security risks</p>
                    </div>
                    <div class="chart-container">
                        <canvas id="riskPyramidChart"></canvas>
                    </div>
                </div>
            </div>
            
            <div class="charts-grid-secondary">
                <div class="chart-card chart-card-wide">
                    <div class="chart-header">
                        <h3>Top Security Categories</h3>
                        <p>Most common vulnerability types detected</p>
                    </div>
                    <div class="chart-container">
                        <canvas id="categoryChart"></canvas>
                    </div>
                </div>
                
                <div class="chart-card">
                    <div class="chart-header">
                        <h3>Security Radar</h3>
                        <p>Multi-dimensional security assessment</p>
                    </div>
                    <div class="chart-container">
                        <canvas id="radarChart"></canvas>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Manifest Analysis -->
        <div class="section">
            <h2>Manifest Analysis</h2>
            {manifest_html}
        </div>
        
        <!-- Categorized Findings -->
        {category_sections}
        
        <!-- Performance Metrics -->
        <div class="section">
            <h2>Scan Performance Metrics</h2>
            <div class="performance-stats">
                <div class="stat-box">
                    <div class="stat-label">Total Scan Time</div>
                    <div class="stat-value">{performance.get('total_scan_time_seconds', 0):.2f}s</div>
                </div>
                <div class="stat-box">
                    <div class="stat-label">Analysis Time</div>
                    <div class="stat-value">{performance.get('analysis_time_seconds', 0):.2f}s</div>
                </div>
                <div class="stat-box">
                    <div class="stat-label">Decompilation Time</div>
                    <div class="stat-value">{performance.get('decompilation_time_seconds', 0):.2f}s</div>
                </div>
            </div>
        </div>
        
        <div class="footer">
            <p><strong>Generated by Matrisks Framework v2.0.0</strong></p>
            <p>Advanced Android Static Security Analysis Platform</p>
            <p>Report ID: {report_info.get('scan_id', '')[:32]}...</p>
        </div>
    </div>
    
    <script>
        {charts_data}
        
        // Severity Distribution Doughnut Chart
        const severityCtx = document.getElementById('severityChart').getContext('2d');
        new Chart(severityCtx, {{
            type: 'doughnut',
            data: {{
                labels: severityLabels,
                datasets: [{{
                    data: severityValues,
                    backgroundColor: severityColors,
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
                            font: {{
                                size: 12,
                                family: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto'
                            }},
                            color: '#000000'
                        }}
                    }},
                    tooltip: {{
                        callbacks: {{
                            label: function(context) {{
                                return context.label + ': ' + context.parsed + ' issues';
                            }}
                        }}
                    }}
                }}
            }}
        }});
        
        // Category Distribution Bar Chart
        const categoryCtx = document.getElementById('categoryChart').getContext('2d');
        new Chart(categoryCtx, {{
            type: 'bar',
            data: {{
                labels: categoryLabels,
                datasets: [{{
                    label: 'Findings',
                    data: categoryCounts,
                    backgroundColor: '#000000',
                    borderColor: '#000000',
                    borderWidth: 1
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                indexAxis: 'y',
                plugins: {{
                    legend: {{
                        display: false
                    }},
                    tooltip: {{
                        callbacks: {{
                            label: function(context) {{
                                return 'Findings: ' + context.parsed.x;
                            }}
                        }}
                    }}
                }},
                scales: {{
                    x: {{
                        beginAtZero: true,
                        ticks: {{
                            stepSize: 1,
                            color: '#000000'
                        }},
                        grid: {{
                            color: '#e0e0e0'
                        }}
                    }},
                    y: {{
                        ticks: {{
                            color: '#000000'
                        }},
                        grid: {{
                            display: false
                        }}
                    }}
                }}
            }}
        }});
        
        // Risk Pyramid Chart
        const pyramidCtx = document.getElementById('riskPyramidChart').getContext('2d');
        new Chart(pyramidCtx, {{
            type: 'bar',
            data: {{
                labels: severityLabels,
                datasets: [{{
                    data: severityValues,
                    backgroundColor: severityColors,
                    borderWidth: 0
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{
                    legend: {{
                        display: false
                    }},
                    tooltip: {{
                        callbacks: {{
                            label: function(context) {{
                                return context.label + ': ' + context.parsed.y + ' issues';
                            }}
                        }}
                    }}
                }},
                scales: {{
                    x: {{
                        ticks: {{
                            color: '#000000',
                            font: {{
                                weight: '600'
                            }}
                        }},
                        grid: {{
                            display: false
                        }}
                    }},
                    y: {{
                        beginAtZero: true,
                        ticks: {{
                            stepSize: 1,
                            color: '#000000'
                        }},
                        grid: {{
                            color: '#e0e0e0'
                        }}
                    }}
                }}
            }}
        }});
        
        // Security Radar Chart
        const radarCtx = document.getElementById('radarChart').getContext('2d');
        const radarLabels = ['Code Quality', 'Network Security', 'Data Storage', 'Authentication', 'Cryptography'];
        const radarScores = [
            Math.max(0, 100 - (severityValues[severityLabels.indexOf('Critical')] || 0) * 10),
            Math.max(0, 100 - (severityValues[severityLabels.indexOf('Warning')] || 0) * 5),
            Math.max(0, 100 - (severityValues[severityLabels.indexOf('Notice')] || 0) * 3),
            Math.max(0, 100 - (severityValues[severityLabels.indexOf('Info')] || 0) * 1),
            Math.max(0, 100 - (severityValues.reduce((a, b) => a + b, 0) * 2))
        ];
        
        new Chart(radarCtx, {{
            type: 'radar',
            data: {{
                labels: radarLabels,
                datasets: [{{
                    label: 'Security Score',
                    data: radarScores,
                    backgroundColor: 'rgba(0, 0, 0, 0.1)',
                    borderColor: '#000000',
                    borderWidth: 2,
                    pointBackgroundColor: '#000000',
                    pointBorderColor: '#ffffff',
                    pointBorderWidth: 2,
                    pointRadius: 4,
                    pointHoverRadius: 6
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{
                    legend: {{
                        display: false
                    }}
                }},
                scales: {{
                    r: {{
                        beginAtZero: true,
                        max: 100,
                        ticks: {{
                            stepSize: 20,
                            color: '#666666',
                            backdropColor: 'transparent'
                        }},
                        grid: {{
                            color: '#e0e0e0'
                        }},
                        pointLabels: {{
                            color: '#000000',
                            font: {{
                                size: 11,
                                weight: '600'
                            }}
                        }}
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
        
        // Scroll to section function
        function scrollToSection(severity) {{
            const elements = document.querySelectorAll('.severity-badge');
            for (let elem of elements) {{
                if (elem.textContent.trim() === severity) {{
                    elem.closest('.finding-row').scrollIntoView({{ behavior: 'smooth', block: 'center' }});
                    elem.closest('.finding-row').style.backgroundColor = '#f5f5f5';
                    setTimeout(() => {{
                        elem.closest('.finding-row').style.backgroundColor = '';
                    }}, 2000);
                    break;
                }}
            }}
        }}
        
        // Animate counts on load
        document.addEventListener('DOMContentLoaded', function() {{
            const counters = document.querySelectorAll('.animate-count');
            counters.forEach(counter => {{
                const target = parseInt(counter.getAttribute('data-target'));
                const duration = 1000;
                const step = target / (duration / 16);
                let current = 0;
                
                const timer = setInterval(() => {{
                    current += step;
                    if (current >= target) {{
                        counter.textContent = target;
                        clearInterval(timer);
                    }} else {{
                        counter.textContent = Math.floor(current);
                    }}
                }}, 16);
            }});
        }});
    </script>
</body>
</html>
"""
    
    return html
