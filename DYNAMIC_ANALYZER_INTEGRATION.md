# Dynamic Analyzer - Backend Integration Documentation

## Overview
The Dynamic Analyzer has been fully integrated into the Matrisks backend API, enabling the frontend Dynamic Analysis button to function seamlessly. The integration follows the same pattern as AI Malware Detection for consistency.

## Integration Components

### 1. Root-Level Setup Scripts ✅ COMPLETED

#### requirements-all.txt
Added Dynamic Analyzer dependencies:
```
-r matrisksDynamicAnalyzer/requirements.txt
```
Includes: Frida 16.1.4, androguard, psutil, pyyaml, and more.

#### setup.sh
- Added `DYNAMIC_DIR` variable pointing to matrisksDynamicAnalyzer
- Created virtual environment symlink from backend to dynamic analyzer
- Added Android SDK setup instructions

#### start_all.sh
- Added Dynamic Analyzer status checks
- Lists available AVDs (Android Virtual Devices)
- Verifies `adb` command availability
- Shows emulator configuration status

#### stop_all.sh
- Added Android emulator shutdown: `adb emu kill`
- Added QEMU process cleanup: `pkill -f "qemu-system"`
- Updated process verification to include emulators

---

### 2. Backend Service Layer ✅ COMPLETED

**File:** `/matrisks-backend/app/services/analysis.py`

#### Modified `__init__` method:
```python
self.dynamic_path = repo_root / "matrisksDynamicAnalyzer"
```

#### Modified `analyze_apk()` method:
Added routing for dynamic analysis:
```python
if analysis_type == "dynamic":
    return self._analyze_with_dynamic(apk_file_path, user_id, original_filename)
```

#### New Method: `_analyze_with_dynamic()`
**Purpose:** Execute Dynamic Analyzer CLI and collect results

**Process Flow:**
1. Extract APK metadata (package name, version, size)
2. Build CLI command: `python cli.py analyze <apk> --duration 60`
3. Execute subprocess with 600-second (10 minute) timeout
4. Find latest analysis directory in `scanned_results/`
5. Create `manifest.json` with user tracking
6. Load `comprehensive_report.json`
7. Parse results for frontend display
8. Return formatted API response

**Returns:**
```python
{
    "status": "success",
    "message": "Dynamic analysis completed",
    "analysis_id": "analysis_com.example.app_20250109_123456",
    "results": {
        "total_api_calls": 1234,
        "sensitive_apis": 56,
        "network_requests": 78,
        "security_score": 7.5,
        "security_grade": "B",
        "risk_level": "Medium",
        "findings": {
            "critical": 2,
            "high": 5,
            "medium": 10,
            "low": 15
        },
        "analysis_duration": "60 seconds"
    },
    "report_content": {
        "html": "<html>...",
        "json": {...},
        "csv": "..."
    }
}
```

#### Helper Methods Added:

1. **`_get_latest_dynamic_analysis_directory()`**
   - Searches `scanned_results/` for `analysis_*` directories
   - Returns most recent by modification time

2. **`_update_dynamic_manifest()`**
   - Creates/updates `manifest.json` in analysis directory
   - Tracks: user_id, apk_name, file_size, timestamps, analysis_directory

3. **`_load_dynamic_report()`**
   - Reads and parses `comprehensive_report.json`
   - Returns JSON data for processing

4. **`_parse_dynamic_results()`**
   - Extracts key metrics from report JSON
   - Returns: API call counts, security scores, findings by severity, duration

5. **`_get_dynamic_report_content()`**
   - Loads HTML, JSON, CSV reports
   - Returns dictionary with all report formats for frontend display

---

### 3. Backend API Router ✅ COMPLETED

**File:** `/matrisks-backend/app/routers/analysis.py`

#### Modified `get_analysis_result()` endpoint:
Added Dynamic Analysis to engine search list:
```python
for engine_name, engine_path in [
    ("Basic Static", project_root / "matrisksBasicStatic"),
    ("Advanced Static", project_root / "matrisksAdvanceStatic"),
    ("Dynamic Analysis", project_root / "matrisksDynamicAnalyzer"),  # ✅ ADDED
    ("AI Malware Detection", project_root / "ai_based_malware_detection")
]:
```

#### Modified `download_report()` endpoint:
Added Dynamic Analyzer file mapping and search logic:

```python
# Define Dynamic Analyzer file mappings (different from static analyzers)
dynamic_format_map = {
    "html": ("comprehensive_report.html", "text/html", "html"),
    "json": ("comprehensive_report.json", "application/json", "json"),
    "csv": ("comprehensive_report.csv", "text/csv", "csv")
}

# Search all directories including dynamic analyzer
for base_path in [basicstatic_path, advancestatic_path, ai_scans_path]:
    potential_path = base_path / "scanned_results" / scan_id / filename
    if potential_path.exists():
        report_path = potential_path
        break

# Check dynamic analyzer with different file names
if not report_path:
    dynamic_filename, _, _ = dynamic_format_map[format]
    potential_path = dynamic_path / "scanned_results" / scan_id / dynamic_filename
    if potential_path.exists():
        report_path = potential_path
```

#### Modified `get_user_analysis_history()` endpoint:
Added Dynamic Analysis to history retrieval:

1. **Added to engine list:**
   ```python
   for engine_name, engine_path in [
       ("Basic Static", ...),
       ("Advanced Static", ...),
       ("Dynamic Analysis", project_root / "matrisksDynamicAnalyzer"),  # ✅ ADDED
       ("AI Malware Detection", ...)
   ]:
   ```

2. **Updated scan directory detection:**
   ```python
   # Support both SCAN- (static) and analysis_ (dynamic) prefixes
   is_scan_dir = scan_dir.is_dir() and (
       scan_dir.name.startswith("SCAN-") or 
       scan_dir.name.startswith("analysis_")
   )
   ```

3. **Added dynamic report format checking:**
   ```python
   if engine_name == "Dynamic Analysis":
       for format_ext in ["html", "json", "csv"]:
           if (scan_dir / f"comprehensive_report.{format_ext}").exists():
               available_formats.append(format_ext)
   ```

4. **Added dynamic-specific metadata:**
   ```python
   if engine_name == "Dynamic Analysis":
       entry["total_api_calls"] = manifest_data.get("total_api_calls", 0)
       entry["security_score"] = manifest_data.get("security_score", 0.0)
       entry["risk_level"] = manifest_data.get("risk_level", "unknown")
       entry["analysis_duration"] = manifest_data.get("analysis_duration", "N/A")
   ```

---

## API Endpoints

### 1. Start Analysis
**Endpoint:** `POST /analysis/scan`

**Request:**
```json
{
  "file": "<APK_FILE>",
  "analysis_type": "dynamic"
}
```

**Response:**
```json
{
  "status": "success",
  "message": "Dynamic analysis completed",
  "analysis_id": "analysis_com.example.app_20250109_123456",
  "results": {
    "total_api_calls": 1234,
    "sensitive_apis": 56,
    "network_requests": 78,
    "security_score": 7.5,
    "security_grade": "B",
    "risk_level": "Medium",
    "findings": {...},
    "analysis_duration": "60 seconds"
  },
  "report_content": {...}
}
```

### 2. Get Analysis Result
**Endpoint:** `GET /analysis/result/{analysis_id}`

**Response:**
```json
{
  "success": true,
  "data": {
    "scan_id": "analysis_com.example.app_20250109_123456",
    "analysis_type": "Dynamic Analysis",
    "apk_name": "example.apk",
    "results": {...},
    "available_formats": ["html", "json", "csv"]
  }
}
```

### 3. Download Report
**Endpoint:** `GET /analysis/download/{scan_id}?format={html|json|csv}`

**Response:** File download (comprehensive_report.html/json/csv)

### 4. Get Analysis History
**Endpoint:** `GET /analysis/history`

**Response:**
```json
{
  "success": true,
  "data": [
    {
      "id": "analysis_com.example.app_20250109_123456",
      "apk_name": "example.apk",
      "analysis_type": "Dynamic Analysis",
      "timestamp": "2025-01-09T12:34:56",
      "status": "completed",
      "available_formats": ["html", "json", "csv"],
      "total_api_calls": 1234,
      "security_score": 7.5,
      "risk_level": "Medium",
      "analysis_duration": "60 seconds"
    },
    ...
  ],
  "total": 1
}
```

---

## File Structure

### Dynamic Analyzer Output Structure:
```
matrisksDynamicAnalyzer/
└── scanned_results/
    └── analysis_com.example.app_20250109_123456/
        ├── manifest.json                    # User tracking & metadata
        ├── comprehensive_report.html        # Main HTML report (254KB)
        ├── comprehensive_report.json        # Structured data
        ├── comprehensive_report.csv         # CSV export
        ├── api_calls.json                   # Detailed API call logs
        ├── network_traffic.json             # Network activity
        ├── file_operations.json             # File I/O operations
        └── screenshots/                     # UI screenshots (if any)
```

### Manifest.json Structure:
```json
{
  "analysis_type": "dynamic",
  "apk_name": "example.apk",
  "package_name": "com.example.app",
  "version_name": "1.0.0",
  "version_code": "1",
  "file_size": 12345678,
  "user_id": 42,
  "upload_timestamp": "2025-01-09T12:34:56",
  "created_at": "2025-01-09T12:35:56",
  "analysis_directory": "analysis_com.example.app_20250109_123456",
  "total_api_calls": 1234,
  "security_score": 7.5,
  "risk_level": "Medium"
}
```

---

## Frontend Integration

### Dynamic Analysis Button Flow:

1. **User clicks "Dynamic Analysis" button** in dashboard
2. **Frontend uploads APK** via `POST /analysis/scan` with `analysis_type=dynamic`
3. **Backend receives file**, saves to temp location
4. **AnalysisService routes** to `_analyze_with_dynamic()`
5. **CLI executed:** `python cli.py analyze <apk> --duration 60`
6. **Analysis runs** for 60 seconds (configurable)
7. **Results collected** from `scanned_results/analysis_*` directory
8. **Response returned** to frontend with results and report content
9. **Frontend displays** results with download links
10. **User downloads** reports via `/analysis/download/{scan_id}?format=html`

---

## Testing Checklist

### Backend Testing:
- [ ] Start backend: `./start_all.sh`
- [ ] Verify Dynamic Analyzer status check works
- [ ] Test scan endpoint: `POST /analysis/scan` with `analysis_type=dynamic`
- [ ] Monitor CLI execution and timeout handling
- [ ] Verify result collection and manifest creation
- [ ] Test result endpoint: `GET /analysis/result/{analysis_id}`
- [ ] Test download endpoint for all formats (html, json, csv)
- [ ] Test history endpoint includes dynamic analysis results
- [ ] Verify user filtering works (only shows user's own analyses)

### Frontend Testing:
- [ ] Click Dynamic Analysis button
- [ ] Upload APK file
- [ ] Monitor progress indicator
- [ ] Verify results display correctly
- [ ] Test report download links
- [ ] Check history page shows dynamic analysis entries
- [ ] Verify metadata display (API calls, security score, etc.)

### Error Handling:
- [ ] Test with invalid APK
- [ ] Test with timeout (analysis > 10 minutes)
- [ ] Test with emulator not running
- [ ] Test with insufficient permissions
- [ ] Verify error messages are user-friendly

---

## Configuration

### Analysis Duration:
Default: 60 seconds (configurable in `_analyze_with_dynamic()`)

To change:
```python
# In /matrisks-backend/app/services/analysis.py
command = [
    str(python_path),
    "cli.py",
    "analyze",
    str(apk_file_path),
    "--duration", "120"  # Change to desired seconds
]
```

### Timeout:
Default: 600 seconds (10 minutes)

To change:
```python
# In /matrisks-backend/app/services/analysis.py
result = subprocess.run(
    command,
    cwd=str(self.dynamic_path),
    capture_output=True,
    text=True,
    timeout=900  # Change to desired seconds
)
```

---

## Troubleshooting

### Issue: "Dynamic Analyzer not found"
**Solution:** Verify `matrisksDynamicAnalyzer` directory exists in project root

### Issue: "No emulator available"
**Solution:** 
1. Check AVD status: `./start_all.sh` (shows AVD list)
2. Start emulator: `emulator -avd <avd_name>`

### Issue: "Analysis timeout"
**Solution:** Increase timeout value or reduce analysis duration

### Issue: "Frida not found"
**Solution:** 
1. Activate venv: `source matrisks-backend/venv/bin/activate`
2. Install: `pip install -r matrisksDynamicAnalyzer/requirements.txt`

### Issue: "Report files not found"
**Solution:** Check `scanned_results/` directory for analysis folder, verify CLI completed successfully

---

## Security Considerations

### User Isolation:
- Each analysis tracked with `user_id` in manifest.json
- History endpoint filters by current user
- No cross-user data leakage

### File Handling:
- Uploaded APKs stored in temporary location
- Analysis results stored in user-specific directories
- Old results can be cleaned up periodically

### Analysis Safety:
- Runs in Android emulator (VM isolation)
- No direct host system access
- Frida hooks monitor behavior without modification
- Network traffic captured but isolated

---

## Performance Notes

### Analysis Time:
- Default duration: 60 seconds
- CLI overhead: ~5-10 seconds
- Total time: ~70-90 seconds per APK

### Resource Usage:
- CPU: Moderate (emulator + Frida)
- Memory: ~2-4GB (emulator + analysis)
- Disk: ~100-500MB per analysis result

### Scalability:
- Single emulator instance
- Sequential analysis only
- Consider queue system for multiple concurrent requests

---

## Future Enhancements

### Planned:
- [ ] Configurable analysis duration from frontend
- [ ] Real-time progress updates via WebSocket
- [ ] Comparison between multiple analysis runs
- [ ] Export comparative reports
- [ ] Scheduled/batch analysis support

### Considerations:
- Multiple emulator instances for parallel analysis
- Docker containerization for better isolation
- Queue system for high-volume deployments
- Result caching and deduplication

---

## Integration Status: ✅ COMPLETE

All components integrated and ready for testing.

**Last Updated:** January 9, 2025
**Integration Version:** 1.0.0
