# Matrisks Dynamic Analyzer

Dynamic analysis module for the Matrisks Android security analysis framework. Provides runtime behavior analysis using Android emulator and Frida instrumentation.

## Features

### Current (Phase 2.5 - Hybrid HTTPS Interception)
-  Emulator-based sandboxed execution
-  Frida instrumentation for API monitoring (215+ APIs)
-  **Hybrid HTTPS Interception**:
  -  **URL metadata capture** (100% success rate)
  -  **Cronet/gRPC detection** (intelligent detection)
  -  **Optional MITM mode** for body capture (user choice via `--mitm-proxy`)
-  Sensitive API call tracking:
  - Network operations (HTTP, OkHttp, URL connections)
  - File I/O operations (read, write, delete)
  - Cryptography (Cipher, MessageDigest)
  - SMS operations
  - Location tracking
  - Contacts access
  - Runtime command execution
  - Dynamic class loading
-  **Intelligent UI Exploration** (network-button prioritization)
-  **Pre-hook Startup** (spawn-paused execution)
-  **Logcat Analysis** (intent/permission extraction)
-  Automated APK installation and analysis
-  Emulator snapshot management
-  JSON report generation
-  CLI interface

### ⚠️ IMPORTANT: HTTPS Body Capture

**Without `--mitm-proxy` flag:**
-  **URL metadata**: 100% captured (all network requests detected)
- ❌ **Request/response bodies**: 0% captured

**With `--mitm-proxy` flag:**
-  **URL metadata**: 100% captured
-  **Request/response bodies**: 80%+ captured

**Why?** Apps using Firebase, Cronet, or gRPC bypass standard Java SSL APIs.

**Solution:**
```bash
# For full body capture, use --mitm-proxy flag
python cli.py analyze app.apk --mitm-proxy

# Then run mitmproxy in another terminal
mitmproxy -p 8080 --set upstream_cert=false
```

### Future Enhancements
- ⏳ Batch analysis (parallel processing)
- ⏳ HTML report generation
- ⏳ Automated AVD setup
- ⏳ Backend API integration
- ⏳ Screenshot capture
- ⏳ Memory dump analysis

## Architecture

```
dynamic_analyzer/
├── core/
│   ├── emulator_manager.py    # Android emulator lifecycle
│   └── orchestrator.py         # Main analysis pipeline
├── instrumentation/
│   ├── frida_manager.py        # Frida runtime instrumentation
│   └── hooks/
│       └── api_monitor.js      # JavaScript hooks for API interception
├── collectors/
│   ├── api_collector.py        # API call data collection
│   └── network_collector.py    # Network traffic logging
├── config/
│   └── analysis_config.yaml    # Configuration file
├── scripts/
│   └── setup.sh                # Automated setup script
└── cli.py                      # Command-line interface
```

## Installation

### Prerequisites
- Python 3.8+
- 2GB free disk space (for Android SDK and system image)
- 4GB RAM minimum, 8GB recommended
- Linux/macOS (Windows WSL2 may work)

### 🚀 Automated Setup (Recommended)

**One-command setup** that installs everything:

```bash
# Install Python dependencies first
pip install -r requirements.txt

# Run automated setup script
python setup.py
```

This script automatically:
1.  Downloads and installs Android SDK command-line tools (~100MB)
2.  Installs system image for Android 11 (~800MB)
3.  Creates optimized AVD (Pixel 5 emulator)
4.  Downloads Frida server for Android
5.  Installs all Python dependencies
6.  Creates configuration file
7.  Verifies setup with tests

**Time:** ~10-15 minutes (depending on internet speed)

### Manual Setup (Alternative)

If you prefer manual setup or the automated script fails:

```bash
# 1. Install Python dependencies
pip install -r requirements.txt

# 2. Install Android SDK manually (see MANUAL_SETUP.md)
```

### Manual Setup

1. **Install Python dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Install Android SDK:**
   - Download Android Command Line Tools: https://developer.android.com/studio#command-tools
   - Extract and add to PATH:
     ```bash
     export ANDROID_SDK_ROOT=$HOME/Android/Sdk
     export PATH=$ANDROID_SDK_ROOT/cmdline-tools/latest/bin:$PATH
     ```

3. **Install SDK components:**
   ```bash
   sdkmanager "platform-tools" "emulator" "system-images;android-30;google_apis;x86_64"
   ```

4. **Create Android Virtual Device (AVD):**
   ```bash
   avdmanager create avd -n Pixel_5_API_30 -k "system-images;android-30;google_apis;x86_64" -d pixel_5
   ```

5. **Download Frida Server:**
   ```bash
   wget https://github.com/frida/frida/releases/download/16.1.4/frida-server-16.1.4-android-x86_64.xz
   unxz frida-server-16.1.4-android-x86_64.xz
   chmod +x frida-server-16.1.4-android-x86_64
   ```

## Configuration

Edit `config/analysis_config.yaml`:

```yaml
emulator:
  avd_name: "Pixel_5_API_30"  # Your AVD name
  boot_timeout: 180

analysis:
  default_duration: 60  # Analysis duration in seconds
  spawn_mode: true      # Spawn app with Frida

frida:
  server_path: "/path/to/frida-server"  # Path to frida-server binary

output:
  base_dir: "./scanned_results"
```

## Usage

### Command Line Interface

**Analyze an APK:**
```bash
python cli.py analyze /path/to/app.apk
```

**Custom duration:**
```bash
python cli.py analyze app.apk --duration 120
```

**Custom AVD:**
```bash
python cli.py analyze app.apk --avd Pixel_5_API_30
```

**Attach to running app (instead of spawn):**
```bash
python cli.py analyze app.apk --attach
```

**List available AVDs:**
```bash
python cli.py list-avds
```

### Python API

```python
from dynamic_analyzer.core.orchestrator import DynamicAnalysisOrchestrator

# Create orchestrator
orchestrator = DynamicAnalysisOrchestrator(
    avd_name="Pixel_5_API_30",
    output_dir="./results",
    frida_server_path="/path/to/frida-server"
)

# Run analysis
results = orchestrator.analyze_apk(
    apk_path="app.apk",
    analysis_duration=60,
    spawn_mode=True
)

# Check results
if results['success']:
    print(f"Total API calls: {results['statistics']['total_calls']}")
    print(f"Sensitive behaviors: {results['sensitive_behaviors']}")
```

## Output

Analysis generates:

```
scanned_results/
└── analysis_<app_name>_<timestamp>/
    ├── api_calls_<timestamp>.json      # API call log
    └── network_traffic_<timestamp>.json # Network activity
```

### API Calls JSON Structure

```json
{
  "metadata": {
    "start_time": "2024-01-01T10:00:00",
    "total_calls": 245
  },
  "statistics": {
    "total_calls": 245,
    "by_category": {
      "network": 45,
      "file": 12,
      "crypto": 8
    }
  },
  "sensitive_behaviors": {
    "network_communication": [
      {
        "action": "HTTP_CONNECT",
        "url": "https://api.example.com/data",
        "method": "POST"
      }
    ],
    "file_operations": [...]
  },
  "api_calls": [...]
}
```

## Monitored APIs

### Network
- `HttpURLConnection.connect()`
- `OkHttpClient.newCall()`
- `URL.openConnection()`

### File I/O
- `FileOutputStream()`
- `FileInputStream()`
- `File.delete()`

### Cryptography
- `Cipher.getInstance()`
- `Cipher.doFinal()`
- `MessageDigest.getInstance()`

### Permissions-sensitive
- `SmsManager.sendTextMessage()` - SMS
- `LocationManager.requestLocationUpdates()` - Location
- `ContentResolver.query()` - Contacts

### Security-critical
- `Runtime.exec()` - Command execution
- `ProcessBuilder.start()` - Process creation
- `DexClassLoader` - Dynamic code loading
- `PathClassLoader` - Class loading

## Troubleshooting

### Emulator won't start
```bash
# List available AVDs
emulator -list-avds

# Test emulator manually
emulator -avd Pixel_5_API_30 -no-snapshot-load
```

### Frida connection fails
```bash
# Check adb connection
adb devices

# Restart adb server
adb kill-server
adb start-server

# Push frida-server manually
adb push frida-server /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/frida-server"
adb shell "/data/local/tmp/frida-server &"
```

### APK installation fails
```bash
# Check emulator has enough space
adb shell df

# Install manually
adb install -r app.apk
```

## Performance Tuning

### Faster Emulator
```yaml
emulator:
  no_window: true    # Headless mode
  no_audio: true
```

### Shorter Analysis
```yaml
analysis:
  default_duration: 30  # Reduce to 30 seconds
```

### Snapshot for Speed
```yaml
analysis:
  create_snapshots: true  # Reuse clean state
```

## Integration with Matrisks Backend

Coming in Phase 2. Will add `/analysis/dynamic` endpoint:

```python
# Future: matrisks-backend/app/routers/analysis.py
@router.post("/analysis/dynamic")
async def dynamic_analysis(apk_file: UploadFile):
    orchestrator = DynamicAnalysisOrchestrator(...)
    results = orchestrator.analyze_apk(apk_file)
    return results
```

## Development

### Adding New Hooks

Edit `instrumentation/hooks/api_monitor.js`:

```javascript
function hookMyAPI() {
    var MyClass = Java.use("com.example.MyClass");
    
    MyClass.myMethod.implementation = function(arg) {
        sendData("custom", "MY_API_CALL", {
            argument: arg
        });
        return this.myMethod(arg);
    };
}

// Add to main execution
Java.perform(function() {
    hookMyAPI();
});
```

### Custom Collectors

Create `collectors/my_collector.py`:

```python
from collectors.api_collector import APICollector

class MyCollector(APICollector):
    def handle_message(self, message, data):
        # Custom processing
        super().handle_message(message, data)
```

## Testing

```bash
# Test with a benign APK
python cli.py analyze test_app.apk --duration 30

# Test emulator only
python -c "from core.emulator_manager import EmulatorManager; \
           m = EmulatorManager('Pixel_5_API_30'); \
           m.start_emulator()"
```

## Contributing

1. Follow existing code structure
2. Add logging for important operations
3. Handle exceptions gracefully
4. Test with multiple APK types
5. Update documentation

## License

Part of the Matrisks Framework

## References

- Frida: https://frida.re/
- Android Emulator: https://developer.android.com/studio/run/emulator
- androguard: https://github.com/androguard/androguard
