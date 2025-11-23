# Quick Start Guide - Matrisks Dynamic Analyzer

## First Time Setup

```bash
# 1. Install Python dependencies
cd /home/mhy/Downloads/matrisks/matrisksDynamicAnalyzer
pip install -r requirements.txt

# 2. Run automated setup (one command, 10-15 minutes)
python setup.py
```

That's it! The script will install everything automatically:
- Android SDK
- Android 11 system image
- Pixel 5 emulator (AVD)
- Frida server
- Configuration file

## Run Your First Analysis

```bash
# Basic analysis (60 seconds)
python cli.py analyze /path/to/app.apk

# Extended UI exploration (3 minutes)
python cli.py analyze /path/to/app.apk --ui-duration 180

# With MITM proxy for HTTPS body capture
python cli.py analyze /path/to/app.apk --mitm-proxy
```

## What You'll Get

Results saved to `scanned_results/SCAN-<timestamp>-<id>/`:
```
├── analysis_report.json         # Complete report
├── api_calls.json               # All 215+ API calls tracked
├── https_traffic.json           # Network traffic
├── logcat.txt                   # Android system logs
├── network_traffic.json         # Low-level network data
└── ui_exploration.json          # UI interaction events
```

## Performance Expectations

### Boot Time
- **First analysis:** ~48s (creates snapshot)
- **Subsequent analyses:** ~15s (loads snapshot) ⚡ **3x faster!**

### Analysis Time
- 60s UI exploration: ~3 minutes total
- 180s UI exploration: ~5 minutes total

### Resource Usage
- RAM: ~3.2GB
- CPU: ~40% (4 cores)
- Disk: ~2GB (SDK + images)

## Common Commands

```bash
# List available AVDs
adb devices

# Check emulator status
python cli.py --help

# View results
cat scanned_results/latest_scan_id.txt
cd scanned_results/SCAN-<id>
cat analysis_report.json | jq .summary
```

## MITM Proxy (Optional)

For capturing HTTPS request/response bodies:

```bash
# Terminal 1: Start mitmproxy
mitmdump -p 8080 --set upstream_cert=false

# Terminal 2: Run analysis with MITM flag
python cli.py analyze app.apk --mitm-proxy --ui-duration 60
```

**Without MITM:**
-  URLs: 100%
- ❌ Bodies: 0%

**With MITM:**
-  URLs: 100%
-  Bodies: 80%+

## Troubleshooting

### Setup fails
```bash
# Check Python version (need 3.8+)
python --version

# Check disk space (need 2GB)
df -h ~

# Manual setup (if automated fails)
# See COMPREHENSIVE_DOCUMENTATION.md for manual steps
```

### Emulator doesn't start
```bash
# Check AVD exists
ls ~/.android/avd/

# Test emulator manually
$ANDROID_SDK_ROOT/emulator/emulator -list-avds
$ANDROID_SDK_ROOT/emulator/emulator -avd Pixel_5_API_30
```

### Frida errors
```bash
# Check Frida version matches
python -c "import frida; print(frida.__version__)"

# Re-download Frida server
ls ~/Android/frida/frida-server
```

## Next Steps

1. **Run your first analysis** (test with any APK)
2. **Check results** in `scanned_results/`
3. **Try MITM mode** for full HTTPS capture
4. **Review documentation** for advanced features

## Need Help?

- **Full documentation:** `COMPREHENSIVE_DOCUMENTATION.md`
- **MobSF comparison:** `ANALYSIS_SUMMARY.md`
- **MITM guide:** `MITM_SETUP_GUIDE.md` or `MITM_QUICK_GUIDE.md`
- **Improvements:** `IMPROVEMENTS_COMPLETED.md`
