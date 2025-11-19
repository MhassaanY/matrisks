import re
import json
from datetime import datetime
from weasyprint import HTML

def parse_metadata(report_content):
    metadata = {}
    metadata_patterns = {
        "Platform": r"^Platform:\s*(.*)$",
        "Package Name": r"^Package Name:\s*(.*)$",
        "Package Version Name": r"^Package Version Name:\s*(.*)$",
        "Package Version Code": r"^Package Version Code:\s*(.*)$",
        "Min Sdk": r"^Min Sdk:\s*(.*)$",
        "Target Sdk": r"^Target Sdk:\s*(.*)$",
        "MD5": r"^MD5\s*:\s*(.*)$",
        "SHA1": r"^SHA1\s*:\s*(.*)$",
        "SHA256": r"^SHA256:\s*(.*)$",
        "SHA512": r"^SHA512:\s*(.*)$",
        "Analyze Signature": r"^Analyze Signature:\s*(.*)$"
    }

    for key, pattern in metadata_patterns.items():
        match = re.search(pattern, report_content, re.MULTILINE)
        if match:
            metadata[key] = match.group(1).strip()
        else:
            metadata[key] = "N/A"
    
    return metadata

def parse_vulnerabilities(report_content):
    vulnerabilities = []
    # Regex to find the start of a vulnerability block and capture severity, category, and title.
    vulnerability_pattern = re.compile(r"^\[([A-Za-z]+)\](?:\s*<([^>]+)>)?\s*(.*)", re.MULTILINE)
    # Regex to find indented lines, which can be part of a description or a code location.
    indented_line_pattern = re.compile(r"^\s+.+")
    # Regex to specifically identify code location lines.
    code_location_pattern = re.compile(r"^(?:=>|->)\s*(.*)")

    # Split the report into lines for easier processing.
    lines = report_content.splitlines()
    line_idx = 0
    while line_idx < len(lines):
        line = lines[line_idx]
        match = vulnerability_pattern.match(line)

        if match:
            severity = match.group(1).strip()
            category = match.group(2).strip() if match.group(2) else "Uncategorized"
            title = match.group(3).strip().rstrip(':')
        else:
            line_idx += 1
            continue

        description_lines = []
        code_locations = []
        
        # Process the lines following the vulnerability header.
        line_idx += 1
        while line_idx < len(lines) and (lines[line_idx].strip() == "" or indented_line_pattern.match(lines[line_idx])):
            processed_line = lines[line_idx].strip()
            if not processed_line:
                # Keep blank lines in descriptions as paragraph breaks.
                description_lines.append("")
                line_idx += 1
                continue

            code_match = code_location_pattern.match(processed_line)
            if code_match:
                # This line is a code location.
                code_locations.append(code_match.group(1).strip())
            else:
                # This line is part of the description.
                description_lines.append(processed_line)
            line_idx += 1
        
        # Join description lines, treating blank lines as paragraph separators.
        description = "<br>".join(description_lines)

        vulnerabilities.append({
            "severity": severity,
            "category": category,
            "title": title,
            "description": description,
            "code_locations": code_locations,
            "references": [] # Placeholder for reference parsing
        })
            
    return vulnerabilities

def generate_html_report(metadata, vulnerabilities, raw_report_text, output_path, template_path="dashboard_template.html"):
    with open(template_path, 'r') as f:
        template = f.read()

    # 1. Create Metadata Table
    metadata_html = '<table class="metadata-table">'
    for key, value in metadata.items():
        metadata_html += f'<tr><td>{key}</td><td>{value}</td></tr>'
    metadata_html += '</table>'

    # 2. Create Summary Stats
    severity_counts = {"Critical": 0, "Warning": 0, "Notice": 0, "Info": 0}
    for v in vulnerabilities:
        if v['severity'] in severity_counts:
            severity_counts[v['severity']] += 1
    
    summary_html = '<table>'
    for severity, count in severity_counts.items():
        summary_html += f'<tr><td>{severity}</td><td>{count}</td></tr>'
    summary_html += '</table>'

    # 3. Create Vulnerability Rows
    vuln_rows_html = ''
    for v in vulnerabilities:
        vuln_rows_html += f'<tr class="expandable" onclick="toggleDetails(this)">'
        vuln_rows_html += f'<td><span class="severity-{v["severity"]}">{v["severity"]}</span></td>'
        vuln_rows_html += f'<td>{v["category"]}</td>'
        vuln_rows_html += f'<td>{v["title"]}</td>'
        vuln_rows_html += f'<td>{len(v["code_locations"])}</td>'
        vuln_rows_html += '</tr>'
        vuln_rows_html += '<tr class="details-row"><td colspan="4">'
        vuln_rows_html += f'<div><b>Description:</b><br>{v["description"]}</div>'
        if v["code_locations"]:
            vuln_rows_html += '<div><b>Code Locations:</b><br>'
            for loc in v["code_locations"]:
                vuln_rows_html += f'<span class="code">{loc}</span><br>'
            vuln_rows_html += '</div>'
        vuln_rows_html += '</td></tr>'

    # 4. Prepare Chart Data
    category_counts = {}
    for v in vulnerabilities:
        category = v['category']
        category_counts[category] = category_counts.get(category, 0) + 1

    severity_data_json = json.dumps(severity_counts)
    category_data_json = json.dumps(category_counts)

    # 5. Replace placeholders
    template = template.replace('{{METADATA_TABLE}}', metadata_html)
    template = template.replace('{{SUMMARY_STATS_TABLE}}', summary_html)
    template = template.replace('{{VULN_ROWS}}', vuln_rows_html)
    template = template.replace('{{SEVERITY_DATA_JSON}}', severity_data_json)
    template = template.replace('{{CATEGORY_DATA_JSON}}', category_data_json)
    template = template.replace('{{RAW_REPORT_TEXT}}', raw_report_text)

    with open(output_path, 'w') as f:
        f.write(template)

def generate_pdf_report(html_path, pdf_path):
    HTML(html_path).write_pdf(pdf_path)

def generate_json_report(metadata, vulnerabilities, output_json_path):
    """Generate JSON format report"""
    import json
    
    report_data = {
        "metadata": metadata,
        "vulnerabilities": vulnerabilities,
        "summary": {
            "total_count": len(vulnerabilities),
            "critical_count": sum(1 for v in vulnerabilities if v.get("severity") == "Critical"),
            "warning_count": sum(1 for v in vulnerabilities if v.get("severity") == "Warning"),
            "notice_count": sum(1 for v in vulnerabilities if v.get("severity") == "Notice"),
            "info_count": sum(1 for v in vulnerabilities if v.get("severity") == "Info")
        }
    }
    
    with open(output_json_path, 'w', encoding='utf-8') as f:
        json.dump(report_data, f, indent=2, ensure_ascii=False)

def generate_csv_report(metadata, vulnerabilities, output_csv_path):
    """Generate CSV format report"""
    import csv
    
    with open(output_csv_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        
        # Write header
        writer.writerow(['Severity', 'Title', 'Description'])
        
        # Write vulnerabilities
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'Info')
            title = vuln.get('title', 'N/A')
            description = vuln.get('description', 'N/A')
            writer.writerow([severity, title, description])

def main(report_path, output_html_path):
    with open(report_path, 'r', encoding='utf-8') as f:
        report_content = f.read()

    metadata = parse_metadata(report_content)
    vulnerabilities = parse_vulnerabilities(report_content)
    
    generate_html_report(metadata, vulnerabilities, report_content, output_html_path)

    pdf_path = output_html_path.replace(".html", ".pdf")
    generate_pdf_report(output_html_path, pdf_path)
    
    # Generate JSON report
    json_path = output_html_path.replace(".html", ".json")
    generate_json_report(metadata, vulnerabilities, json_path)
    
    # Generate CSV report
    csv_path = output_html_path.replace(".html", ".csv")
    generate_csv_report(metadata, vulnerabilities, csv_path)

if __name__ == '__main__':
    # Example usage:
    # main("path/to/report.txt", "path/to/report.html")
    pass
