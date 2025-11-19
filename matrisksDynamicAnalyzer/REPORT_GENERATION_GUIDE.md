# Dynamic Analyzer - Report Generation Guide

## Overview

The Dynamic Analyzer now includes a comprehensive report generation system that produces professional security reports in three formats: JSON, CSV, and HTML. This system is modeled after the Advanced Static Analyzer's reporting capabilities.

## Report Formats

### 1. JSON Report (`comprehensive_report.json`)
**Purpose**: Complete structured data for programmatic analysis

**Structure**:
- `report_info`: Metadata (timestamp, version, analyzer type)
- `app_info`: Application details (package name, analysis timestamp)
- `security_assessment`: Security score, grade, and risk level
- `api_analysis`: API call statistics and breakdowns by category
- `sensitive_behaviors`: Network, file, crypto, contacts, and dynamic loading activities
- `network_analysis`: TCP/UDP and HTTPS traffic with sensitive data detection
- `system_monitoring`: Logcat events (crashes, camera, mic, permissions, intents)
- `ui_exploration`: UI automation statistics
- `risk_categorization`: Findings grouped by risk level (critical/high/medium/low/info)
- `raw_data`: Complete raw analysis data

### 2. CSV Report (`comprehensive_report.csv`)
**Purpose**: Tabular format for spreadsheet analysis

**Columns**:
- Timestamp
- Category (network/crypto/file/system/etc)
- Type (specific API or event type)
- Action (method/function called)
- Risk Level
- Details
- Location/URL (for network calls)
- Algorithm/Method (for crypto operations)
- Additional Info

### 3. HTML Report (`comprehensive_report.html`)
**Purpose**: Visual dashboard for quick assessment

**Features**:
- Color-coded security metrics
- Interactive sections
- Summary statistics
- Risk level indicators
- Easy-to-read formatting

## Security Scoring System

### Score Range: 0-100

**Calculation Method**: Deduction-based scoring
- Start at 100 points
- Deduct points for risky behaviors:
  - **Runtime operations**: -5 points each (reflection, native loading, dex loading)
  - **ClassLoader operations**: -3 points each
  - **Network calls**: -2 points each
  - **Crypto operations**: -1 point each
  - **File operations**: -1 point each
  - **SMS/Phone operations**: -5 points each
  - **Location access**: -3 points each
  - **Contact access**: -3 points each

### Letter Grades
- **A**: 90-100 (Excellent security)
- **B**: 80-89 (Good security)
- **C**: 70-79 (Acceptable security)
- **D**: 60-69 (Poor security)
- **F**: 0-59 (Critical security concerns)

### Risk Levels
- **Low**: Score ≥ 80
- **Medium**: Score 60-79
- **High**: Score 30-59
- **Critical**: Score < 30

## Automatic Report Generation

Reports are automatically generated at the end of each analysis. No additional action required!

**Location**: `scanned_results/analysis_{app_name}_{timestamp}/`

**Files Created**:
```
analysis_myapp_20231115_120000/
├── api_calls.json
├── network_traffic.json
├── https_traffic.json
├── logcat_analysis.json
├── ui_exploration.json
├── comprehensive_report.json    ← NEW
├── comprehensive_report.csv     ← NEW
└── comprehensive_report.html    ← NEW
```

## Batch Report Generation

Use the `batch_report_generator.py` tool to generate reports for multiple analyses.

### Usage Examples

#### Generate reports for all analyses:
```bash
python batch_report_generator.py --all
```

#### Generate reports for the last N analyses:
```bash
python batch_report_generator.py --last 5
```

#### Generate reports for a specific analysis:
```bash
python batch_report_generator.py -d scanned_results/analysis_myapp_20231115_120000
```

#### Generate reports matching a pattern:
```bash
python batch_report_generator.py --pattern "traffic-racer"
```

#### Use a different root directory:
```bash
python batch_report_generator.py --all --root /path/to/results
```

#### Quiet mode (minimal output):
```bash
python batch_report_generator.py --all -q
```

### Command-Line Options

| Option | Description |
|--------|-------------|
| `-d, --directory` | Process specific analysis directory |
| `--all` | Process all analyses in root directory |
| `--last N` | Process last N analyses |
| `--pattern` | Match pattern in directory names |
| `--root` | Root directory (default: scanned_results) |
| `-q, --quiet` | Minimal output |

## Interpreting Reports

### Security Assessment

**Example**:
```json
{
  "security_score": 65,
  "security_grade": "D",
  "risk_level": "Medium",
  "summary": "Security score: 65/100 (Grade: D)"
}
```

**Interpretation**:
- Score of 65 indicates poor security practices
- Grade D suggests significant security concerns
- Medium risk level requires attention
- Review the risk categorization section for specific issues

### Risk Categorization

Findings are grouped by severity:

**Critical**: Immediate action required
- Examples: SMS/phone access, suspicious native loading, excessive reflection

**High**: High priority for review
- Examples: Dynamic code loading, location tracking, contact access

**Medium**: Should be reviewed
- Examples: Crypto operations, frequent network calls, file operations

**Low**: Monitor but generally acceptable
- Examples: Standard API calls, normal network traffic

**Info**: Informational only
- Examples: UI events, standard system operations

### API Analysis

Review the breakdown by category to understand app behavior:
- **Network**: All network-related API calls
- **Crypto**: Cryptographic operations
- **File**: File system access
- **SMS**: SMS/Phone operations
- **Location**: Location access
- **Contacts**: Contact database access
- **Runtime**: Reflection and dynamic loading
- **ClassLoader**: Custom class loading

### Network Analysis

**HTTPS Traffic**:
- Review URLs accessed
- Check for sensitive data in parameters
- Look for hardcoded API keys or tokens

**TCP/UDP Traffic**:
- Monitor connections to unknown hosts
- Check for unusual ports
- Review data patterns

### System Monitoring

**Logcat Events**:
- Crashes: App stability issues
- Camera/Mic: Privacy-sensitive operations
- Permissions: Runtime permission requests
- Intents: Inter-component communication

## Best Practices

### 1. Review Reports After Each Analysis
- Check security score and grade
- Focus on critical and high-risk findings
- Investigate unusual network activity

### 2. Compare Across Versions
- Generate reports for different app versions
- Track security score changes
- Monitor new risky behaviors

### 3. Use CSV for Detailed Analysis
- Import into Excel/LibreOffice
- Filter by risk level or category
- Create pivot tables for statistics

### 4. Share HTML Reports
- Easy to view in any browser
- Professional appearance for stakeholders
- No technical knowledge required

### 5. Archive JSON Reports
- Complete data for future reference
- Can be re-processed or analyzed
- Supports automated workflows

## Troubleshooting

### No Reports Generated

**Check**:
1. Analysis directory exists and contains required files
2. All analysis files are present (api_calls.json, network_traffic.json, etc.)
3. Check for error messages in console output

### Incomplete Data in Reports

**Check**:
1. Analysis ran to completion
2. App was properly exercised during analysis
3. Frida hooks captured data successfully

### Security Score Seems Wrong

**Remember**:
- Score is based on detected API calls
- More risky operations = lower score
- Score reflects potential risks, not actual vulnerabilities
- Review the risk categorization section for details

## Technical Details

### Data Sources
- `api_calls.json`: All Frida-hooked API calls
- `network_traffic.json`: TCP/UDP traffic
- `https_traffic.json`: HTTPS requests/responses
- `logcat_analysis.json`: System logs and events
- `ui_exploration.json`: UI automation results

### Report Generator Class
**File**: `report_generator.py`

**Main Class**: `DynamicReportGenerator`

**Key Methods**:
- `generate_json_report()`: Creates comprehensive JSON
- `generate_csv_report()`: Creates tabular CSV
- `generate_html_report()`: Creates visual HTML
- `save_all_reports()`: Generates all three formats

### Integration Point
**File**: `core/orchestrator.py`

Reports are generated automatically after analysis completion via:
```python
from report_generator import DynamicReportGenerator
report_gen = DynamicReportGenerator(analysis_dir)
report_paths = report_gen.save_all_reports()
```

## Examples

### Example 1: Good Security Score
```
Security Score: 85/100
Grade: B
Risk Level: Low
```
**Interpretation**: App uses mostly standard APIs with few risky operations. Safe for general use.

### Example 2: Poor Security Score
```
Security Score: 25/100
Grade: F
Risk Level: Critical
```
**Interpretation**: App exhibits many risky behaviors (reflection, dynamic loading, excessive network calls). Requires detailed security review.

### Example 3: Medium Risk App
```
Security Score: 68/100
Grade: D
Risk Level: Medium
```
**Interpretation**: App has some concerning behaviors but may be acceptable depending on functionality. Review specific risk categories.

## Support

For issues or questions about the report generation system:
1. Check this guide first
2. Review the example reports in `scanned_results/`
3. Examine the source code in `report_generator.py`
4. Check the batch tool documentation in `batch_report_generator.py`

---

**Version**: 1.0  
**Last Updated**: November 2024  
**Analyzer**: Matrisks Dynamic Analyzer
