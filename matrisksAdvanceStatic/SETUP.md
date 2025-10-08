# MatRisks Advanced Static Analysis - Setup Guide

## Prerequisites

This tool requires the following dependencies:

### 1. Python Dependencies
All Python packages are listed in `requirements.txt` and will be installed via the main setup script.

**Key requirement: androguard >= 4.1.2**

### 2. JADX (Optional - for Java decompilation)

JADX is used for decompiling APK files to Java source code. While optional, it enhances the analysis capabilities.

#### Download JADX:

**Option A: Download Pre-built Binary (Recommended)**
1. Visit: https://github.com/skylot/jadx/releases
2. Download the latest `jadx-<version>.zip` (e.g., `jadx-1.5.3.zip`)
3. Extract to `matrisksAdvanceStatic/`:
   ```bash
   cd matrisksAdvanceStatic
   wget https://github.com/skylot/jadx/releases/download/v1.5.3/jadx-1.5.3.zip
   unzip jadx-1.5.3.zip
   chmod +x bin/jadx
   ```

**Option B: Use System-installed JADX**
```bash
# Ubuntu/Debian
sudo apt-get install jadx

# macOS
brew install jadx
```

#### Verify JADX Installation:
```bash
./bin/jadx --version
# or if system-installed:
jadx --version
```

### 3. Test Applications (Optional)

For testing the analysis engine, you can download sample APKs:

```bash
cd matrisksAdvanceStatic/test_applications

# Download DIVA Android (Damn Insecure and Vulnerable App)
wget https://github.com/payatu/diva-android/raw/master/diva-beta.apk

# Or use your own APK files for testing
```

## Installation

From the main project root:

```bash
cd /home/mhy/matrisks

# Install all dependencies (includes advanced static requirements)
source matrisks-backend/venv/bin/activate
pip install -r requirements-all.txt
```

## Usage

### Via Web Interface (Recommended)

1. Start the full stack:
   ```bash
   cd /home/mhy/matrisks
   ./start_all.sh
   ```

2. Open browser: http://localhost:5173
3. Upload APK and select "Advanced Analysis"

### Command Line (Direct)

```bash
cd matrisksAdvanceStatic
python matrisks.py /path/to/your/app.apk

# With JADX decompilation:
python matrisks.py /path/to/your/app.apk --jadx-path ./bin/jadx

# Or if JADX is system-installed:
python matrisks.py /path/to/your/app.apk --jadx-path jadx
```

## Security Vectors

The advanced static analysis includes 33 security check vectors:

1. ADB Debugging Detection
2. App Overview & Metadata
3. Base64 Encoding/Decoding
4. Debug Mode Detection
5. Cryptography Analysis
6. WebView Security
7. SSL/TLS Implementation
8. Permission Analysis
9. HTTP vs HTTPS Usage
10. Root Detection
11. Runtime Execution (Runtime.exec)
12. Native Methods (JNI)
13. Sensitive Data Access
14. Storage Security
15. SQLite Database Security
16. Fragment Injection
17. Dynamic Code Loading
18. Hardcoded Secrets
19. SMS/Telephony Access
20. Keystore & Certificate Security
21. Master Key Detection
22. Shared User ID
23. Package Signatures
24. Install Source Verification
25. GCM/FCM Manifest Checks
26. Screenshot Prevention
27. Strandhogg Vulnerability
28. XXE Injection
29. Security Methods & Classes
30. Insecure Component Interaction
31. Insecure Data Storage
32. Dependency Analysis
33. Framework Security

## Troubleshooting

### ModuleNotFoundError: No module named 'androguard'
```bash
pip install androguard>=4.1.2
```

### JADX not found
Either:
1. Download and extract JADX to `bin/` directory (see instructions above)
2. Install JADX system-wide and specify `--jadx-path jadx`
3. Run without decompilation (tool will still work for most security checks)

### ImportError related to androguard
Make sure you have androguard 4.1.2 or higher:
```bash
pip uninstall androguard
pip install androguard>=4.1.2
```

## Output Formats

The analysis generates reports in multiple formats:

- **HTML**: Interactive web report
- **JSON**: Machine-readable data
- **CSV**: Spreadsheet-compatible format
- **PDF**: Printable document (requires WeasyPrint)

All reports are saved in `scanned_results/SCAN-<timestamp>/`

## Integration with MatRisks Platform

This tool is integrated into the main MatRisks platform and is called automatically when users select "Advanced Analysis" from the web interface. Results are stored in the database and displayed in the user's analysis history.
