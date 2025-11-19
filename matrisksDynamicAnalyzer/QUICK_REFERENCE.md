# 📊 Dynamic Analyzer Report Generation - Quick Reference

## 🎯 What Was Created

### 1. Main Report Generator
**File**: `report_generator.py` (1,100+ lines)  
**Purpose**: Generate JSON, CSV, and HTML reports from analysis data  
**Usage**: Automatic (runs after each analysis) or manual

### 2. Batch Processing Tool
**File**: `batch_report_generator.py` (200+ lines)  
**Purpose**: Generate reports for multiple analyses at once  
**Usage**: Command-line tool

### 3. Documentation
**Files**: 
- `REPORT_GENERATION_GUIDE.md` - Complete user guide
- `REPORT_GENERATION_SUMMARY.md` - Implementation details

---

## ⚡ Quick Commands

### Run Analysis (Reports Auto-Generated)
```bash
python cli.py analyze /path/to/app.apk
```

### Generate Report for Single Analysis
```bash
python report_generator.py scanned_results/analysis_myapp_20231115_120000/
```

### Generate Reports for All Analyses
```bash
python batch_report_generator.py --all
```

### Generate Reports for Last 5 Analyses
```bash
python batch_report_generator.py --last 5
```

### Generate Reports Matching Pattern
```bash
python batch_report_generator.py --pattern "myapp"
```

---

## 📁 Output Files

Each analysis directory now contains:
```
analysis_myapp_20231115_120000/
├── api_calls.json                    (existing)
├── network_traffic.json              (existing)
├── https_traffic.json                (existing)
├── logcat_analysis.json              (existing)
├── ui_exploration.json               (existing)
├── comprehensive_report.json    ✨ NEW - Complete data
├── comprehensive_report.csv     ✨ NEW - Spreadsheet
└── comprehensive_report.html    ✨ NEW - Visual dashboard
```

---

## 🏆 Security Scoring

### Score Formula
Start at 100, deduct points for risky behaviors:
- **Runtime operations**: -5 pts each
- **ClassLoader**: -3 pts each  
- **Network calls**: -2 pts each
- **Crypto/File**: -1 pt each
- **SMS/Location/Contacts**: -5/-3/-3 pts

### Grades
- **A (90-100)**: Excellent ✅
- **B (80-89)**: Good 👍
- **C (70-79)**: Acceptable ⚠️
- **D (60-69)**: Poor 🟡
- **F (0-59)**: Critical 🔴

### Risk Levels
- **Low**: Score ≥ 80
- **Medium**: Score 60-79
- **High**: Score 30-59
- **Critical**: Score < 30

---

## 📊 Report Formats

### JSON Report
- **Size**: ~50-200KB
- **Purpose**: Complete structured data
- **Sections**: 10 (report_info, app_info, security_assessment, etc.)
- **Use**: Automation, archival, programmatic analysis

### CSV Report
- **Size**: ~20-100KB
- **Purpose**: Tabular data for spreadsheets
- **Columns**: 9 (Timestamp, Category, Type, Action, Risk, Details, etc.)
- **Use**: Excel analysis, filtering, pivot tables

### HTML Report
- **Size**: ~10-20KB
- **Purpose**: Visual dashboard
- **Features**: Color-coded, responsive, professional
- **Use**: Quick review, stakeholder reports

---

## ✅ Test Status

**Tested On**: 3 Traffic Racer analyses  
**Success Rate**: 100% (3/3)  
**Reports Generated**: 9 files (3 × JSON/CSV/HTML)  
**File Sizes**: JSON 124KB, CSV 49KB, HTML 13KB  
**Status**: ✅ Production Ready

---

## 🔍 Example Results

### Traffic Racer Mod Analysis
**Package**: com.skgames.trafficracer

**Security Assessment**:
- Score: **10/100**
- Grade: **F**
- Risk: **Critical**

**Key Findings**:
- 59 total API calls captured
- 22 crypto operations
- 16 network calls
- 8 dynamic class loading operations
- 5 runtime/reflection operations

**Risk Distribution**:
- Critical: 5 findings
- High: 16 findings
- Medium: 31 findings
- Low: 7 findings

---

## 📚 Documentation Files

1. **REPORT_GENERATION_GUIDE.md**
   - How to use the report system
   - Interpreting security scores
   - Command examples
   - Troubleshooting

2. **REPORT_GENERATION_SUMMARY.md**
   - Implementation details
   - Test results
   - Technical architecture
   - Verification checklist

3. **QUICK_REFERENCE.md** (this file)
   - Quick commands
   - File locations
   - Score cheat sheet

---

## 🚀 Next Steps

### For Users
1. ✅ Run new analysis - reports auto-generate
2. ✅ Use batch tool to process existing analyses
3. ✅ Open HTML report in browser for quick review
4. ✅ Use CSV for detailed spreadsheet analysis
5. ✅ Archive JSON for long-term storage

### For Developers
1. Review `report_generator.py` for customization
2. Adjust scoring weights if needed
3. Add custom report sections
4. Integrate with CI/CD pipelines

---

## 📞 Help

### View Report
```bash
# Open HTML report in browser
firefox scanned_results/analysis_*/comprehensive_report.html

# Or
google-chrome scanned_results/analysis_*/comprehensive_report.html
```

### Check Report Contents
```bash
# Quick JSON structure
jq 'keys' scanned_results/analysis_*/comprehensive_report.json

# Security score
jq '.security_assessment' scanned_results/analysis_*/comprehensive_report.json

# View CSV
column -t -s, scanned_results/analysis_*/comprehensive_report.csv | less
```

### Troubleshooting
- **No reports?** Check analysis completed successfully
- **Empty reports?** Verify analysis captured data (check api_calls.json)
- **Wrong score?** Review risk categorization section for details
- **Errors?** Run with verbose: `python report_generator.py -v <dir>`

---

## 🎉 Summary

**Status**: ✅ Complete and Working  
**Integration**: ✅ Automatic  
**Testing**: ✅ Verified on 3 analyses  
**Documentation**: ✅ Complete  
**Production Ready**: ✅ Yes

The Dynamic Analyzer now has professional reporting capabilities matching the Advanced Static Analyzer!

---

**Version**: 1.0  
**Last Updated**: November 17, 2024  
**System**: Matrisks Dynamic Analyzer
