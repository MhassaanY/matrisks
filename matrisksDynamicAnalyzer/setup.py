#!/usr/bin/env python3
"""
Automated Setup Script for Matrisks Dynamic Analyzer
Handles Android SDK, AVD creation, and Frida server download
"""
import os
import sys
import subprocess
import platform
import urllib.request
import tarfile
import zipfile
from pathlib import Path
import shutil

def print_header(text):
    """Print formatted header"""
    print("\n" + "=" * 70)
    print(f"  {text}")
    print("=" * 70 + "\n")

def print_step(step_num, text):
    """Print step number"""
    print(f"\n[{step_num}/6] {text}")
    print("-" * 70)

def check_command(cmd):
    """Check if command exists"""
    return shutil.which(cmd) is not None

def get_android_sdk_root():
    """Get or set Android SDK root"""
    # Check environment variable
    sdk_root = os.environ.get('ANDROID_SDK_ROOT')
    if sdk_root and Path(sdk_root).exists():
        return Path(sdk_root)
    
    # Check default locations
    home = Path.home()
    possible_locations = [
        home / 'Android' / 'Sdk',
        home / 'Library' / 'Android' / 'sdk',  # macOS
        Path('/opt/android-sdk'),  # Linux system-wide
    ]
    
    for loc in possible_locations:
        if loc.exists():
            return loc
    
    # Use default
    default_sdk = home / 'Android' / 'Sdk'
    return default_sdk

def download_file(url, dest_path, desc="file"):
    """Download file with progress"""
    print(f"  Downloading {desc}...")
    print(f"  URL: {url}")
    
    try:
        def reporthook(block_num, block_size, total_size):
            downloaded = block_num * block_size
            if total_size > 0:
                percent = min(downloaded * 100 / total_size, 100)
                size_mb = downloaded / (1024 * 1024)
                total_mb = total_size / (1024 * 1024)
                print(f"\r  Progress: {percent:.1f}% ({size_mb:.1f}/{total_mb:.1f} MB)", end='')
        
        urllib.request.urlretrieve(url, dest_path, reporthook)
        print()  # New line after progress
        return True
    except Exception as e:
        print(f"\n  ✗ Download failed: {e}")
        return False

def setup_android_sdk():
    """Setup Android SDK and command-line tools"""
    print_step(1, "Setting up Android SDK")
    
    sdk_root = get_android_sdk_root()
    print(f"  SDK location: {sdk_root}")
    
    # Create SDK directory
    sdk_root.mkdir(parents=True, exist_ok=True)
    
    # Check if SDK tools already exist
    cmdline_tools_dir = sdk_root / 'cmdline-tools' / 'latest'
    if cmdline_tools_dir.exists() and (cmdline_tools_dir / 'bin' / 'sdkmanager').exists():
        print("  ✓ Android SDK command-line tools already installed")
        return str(sdk_root)
    
    print("  Downloading Android SDK command-line tools...")
    
    # Determine OS
    system = platform.system().lower()
    if system == 'linux':
        url = "https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip"
    elif system == 'darwin':  # macOS
        url = "https://dl.google.com/android/repository/commandlinetools-mac-11076708_latest.zip"
    else:
        print(f"  ✗ Unsupported OS: {system}")
        return None
    
    # Download
    zip_path = sdk_root / 'cmdline-tools.zip'
    if not download_file(url, zip_path, "SDK command-line tools"):
        return None
    
    # Extract
    print("  Extracting...")
    try:
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(sdk_root / 'cmdline-tools')
        
        # Rename to 'latest'
        extracted_dir = sdk_root / 'cmdline-tools' / 'cmdline-tools'
        if extracted_dir.exists():
            extracted_dir.rename(cmdline_tools_dir)
        
        zip_path.unlink()  # Delete zip
        print("  ✓ SDK command-line tools installed")
    except Exception as e:
        print(f"  ✗ Extraction failed: {e}")
        return None
    
    # Set environment variable
    os.environ['ANDROID_SDK_ROOT'] = str(sdk_root)
    
    return str(sdk_root)

def install_sdk_components(sdk_root):
    """Install required SDK components"""
    print_step(2, "Installing SDK components")
    
    sdkmanager = Path(sdk_root) / 'cmdline-tools' / 'latest' / 'bin' / 'sdkmanager'
    if not sdkmanager.exists():
        print(f"  ✗ sdkmanager not found at {sdkmanager}")
        return False
    
    # Add to PATH temporarily
    sdk_bin = Path(sdk_root) / 'cmdline-tools' / 'latest' / 'bin'
    os.environ['PATH'] = f"{sdk_bin}:{os.environ['PATH']}"
    
    components = [
        "platform-tools",  # adb
        "emulator",  # Android Emulator
        "system-images;android-30;google_apis;x86_64",  # Android 11 system image
        "platforms;android-30",  # Android 11 platform
    ]
    
    print(f"  Installing: {', '.join(components)}")
    print("  This may take 5-10 minutes...")
    
    try:
        # Accept licenses first
        print("\n  Accepting licenses...")
        subprocess.run(
            [str(sdkmanager), "--licenses"],
            input=b'y\n' * 10,  # Accept all licenses
            check=True,
            timeout=60
        )
        
        # Install components
        print("\n  Installing components...")
        subprocess.run(
            [str(sdkmanager), "--install"] + components,
            check=True,
            timeout=600  # 10 minutes timeout
        )
        
        print("\n  ✓ SDK components installed")
        return True
    except subprocess.TimeoutExpired:
        print("  ✗ Installation timed out (slow network?)")
        return False
    except Exception as e:
        print(f"  ✗ Installation failed: {e}")
        return False

def create_avd(sdk_root, avd_name="Pixel_5_API_30", android_version="30"):
    """Create Android Virtual Device"""
    print_step(3, f"Creating AVD: {avd_name}")
    
    avdmanager = Path(sdk_root) / 'cmdline-tools' / 'latest' / 'bin' / 'avdmanager'
    
    # Check if AVD already exists
    avd_dir = Path.home() / '.android' / 'avd' / f'{avd_name}.avd'
    if avd_dir.exists():
        print(f"  ✓ AVD '{avd_name}' already exists")
        return avd_name
    
    print(f"  Creating AVD with Android {android_version}...")
    
    try:
        subprocess.run(
            [
                str(avdmanager), "create", "avd",
                "-n", avd_name,
                "-k", f"system-images;android-{android_version};google_apis;x86_64",
                "-d", "pixel_5"
            ],
            input=b'no\n',  # Don't create custom hardware profile
            check=True,
            timeout=60
        )
        
        print(f"  ✓ AVD '{avd_name}' created")
        return avd_name
    except Exception as e:
        print(f"  ✗ AVD creation failed: {e}")
        return None

def download_frida_server(sdk_root):
    """Download Frida server for Android"""
    print_step(4, "Downloading Frida server")
    
    # Get Frida version from Python package
    try:
        import frida
        frida_version = frida.__version__
        print(f"  Frida Python version: {frida_version}")
    except ImportError:
        print("  ✗ Frida not installed. Run: pip install frida frida-tools")
        return None
    
    # Download matching frida-server
    frida_dir = Path(sdk_root).parent / 'frida'
    frida_dir.mkdir(parents=True, exist_ok=True)
    
    frida_server_path = frida_dir / 'frida-server'
    if frida_server_path.exists():
        print(f"  ✓ frida-server already downloaded")
        return str(frida_server_path)
    
    # Download URL (x86_64 for emulator)
    url = f"https://github.com/frida/frida/releases/download/{frida_version}/frida-server-{frida_version}-android-x86_64.xz"
    xz_path = frida_dir / f'frida-server-{frida_version}-android-x86_64.xz'
    
    if not download_file(url, xz_path, f"frida-server {frida_version}"):
        return None
    
    # Extract .xz file
    print("  Extracting...")
    try:
        import lzma
        with lzma.open(xz_path, 'rb') as f_in:
            with open(frida_server_path, 'wb') as f_out:
                f_out.write(f_in.read())
        
        # Make executable
        frida_server_path.chmod(0o755)
        xz_path.unlink()  # Delete .xz
        
        print(f"  ✓ frida-server downloaded to {frida_server_path}")
        return str(frida_server_path)
    except Exception as e:
        print(f"  ✗ Extraction failed: {e}")
        return None

def install_python_dependencies():
    """Install Python dependencies"""
    print_step(5, "Installing Python dependencies")
    
    requirements_file = Path(__file__).parent / 'requirements.txt'
    if not requirements_file.exists():
        print(f"  ✗ requirements.txt not found at {requirements_file}")
        return False
    
    try:
        subprocess.run(
            [sys.executable, '-m', 'pip', 'install', '-r', str(requirements_file)],
            check=True,
            timeout=300
        )
        print("  ✓ Python dependencies installed")
        return True
    except Exception as e:
        print(f"  ✗ Installation failed: {e}")
        return False

def create_config_file(sdk_root, avd_name, frida_server_path):
    """Create configuration file"""
    print_step(6, "Creating configuration file")
    
    config_file = Path(__file__).parent / 'config.py'
    
    config_content = f'''"""
Auto-generated configuration for Matrisks Dynamic Analyzer
Generated by: setup.py
"""
import os

# Android SDK
ANDROID_SDK_ROOT = "{sdk_root}"
os.environ['ANDROID_SDK_ROOT'] = ANDROID_SDK_ROOT

# Emulator
DEFAULT_AVD_NAME = "{avd_name}"
DEFAULT_EMULATOR_PORT = 5554

# Frida
FRIDA_SERVER_PATH = "{frida_server_path}"

# Analysis
DEFAULT_ANALYSIS_DURATION = 60  # seconds
DEFAULT_UI_DURATION = 180  # seconds

# Output
OUTPUT_DIR = "scanned_results"
'''
    
    try:
        config_file.write_text(config_content)
        print(f"  ✓ Configuration saved to {config_file}")
        return True
    except Exception as e:
        print(f"  ✗ Failed to create config: {e}")
        return False

def test_setup(sdk_root, avd_name):
    """Test the setup"""
    print_header("Testing Setup")
    
    success = True
    
    # Test 1: adb
    print("  [1/4] Testing adb...")
    adb = Path(sdk_root) / 'platform-tools' / 'adb'
    if adb.exists():
        try:
            result = subprocess.run([str(adb), 'version'], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                print(f"    ✓ adb working: {result.stdout.split()[4]}")
            else:
                print("    ✗ adb not working")
                success = False
        except Exception as e:
            print(f"    ✗ adb test failed: {e}")
            success = False
    else:
        print("    ✗ adb not found")
        success = False
    
    # Test 2: emulator
    print("  [2/4] Testing emulator...")
    emulator = Path(sdk_root) / 'emulator' / 'emulator'
    if emulator.exists():
        try:
            result = subprocess.run([str(emulator), '-version'], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                print(f"    ✓ emulator working")
            else:
                print("    ✗ emulator not working")
                success = False
        except Exception as e:
            print(f"    ✗ emulator test failed: {e}")
            success = False
    else:
        print("    ✗ emulator not found")
        success = False
    
    # Test 3: AVD
    print(f"  [3/4] Testing AVD '{avd_name}'...")
    avd_dir = Path.home() / '.android' / 'avd' / f'{avd_name}.avd'
    if avd_dir.exists():
        print(f"    ✓ AVD exists at {avd_dir}")
    else:
        print(f"    ✗ AVD not found")
        success = False
    
    # Test 4: Frida
    print("  [4/4] Testing Frida...")
    try:
        import frida
        print(f"    ✓ Frida Python: {frida.__version__}")
    except ImportError:
        print("    ✗ Frida not installed")
        success = False
    
    return success

def main():
    """Main setup function"""
    print_header("Matrisks Dynamic Analyzer - Automated Setup")
    
    print("This script will:")
    print("  • Install Android SDK and command-line tools")
    print("  • Download system images (Android 11)")
    print("  • Create Android Virtual Device (AVD)")
    print("  • Download Frida server")
    print("  • Install Python dependencies")
    print("  • Create configuration file")
    print("\nEstimated time: 10-15 minutes")
    print("Required disk space: ~2GB")
    print("\nPress Enter to continue or Ctrl+C to cancel...")
    
    try:
        input()
    except KeyboardInterrupt:
        print("\n\nSetup cancelled.")
        return 1
    
    # Step 1: Setup Android SDK
    sdk_root = setup_android_sdk()
    if not sdk_root:
        print("\n✗ Failed to setup Android SDK")
        return 1
    
    # Step 2: Install SDK components
    if not install_sdk_components(sdk_root):
        print("\n✗ Failed to install SDK components")
        return 1
    
    # Step 3: Create AVD
    avd_name = create_avd(sdk_root)
    if not avd_name:
        print("\n✗ Failed to create AVD")
        return 1
    
    # Step 4: Download Frida server
    frida_server_path = download_frida_server(sdk_root)
    if not frida_server_path:
        print("\n✗ Failed to download Frida server")
        return 1
    
    # Step 5: Install Python dependencies
    if not install_python_dependencies():
        print("\n✗ Failed to install Python dependencies")
        return 1
    
    # Step 6: Create config
    if not create_config_file(sdk_root, avd_name, frida_server_path):
        print("\n✗ Failed to create configuration")
        return 1
    
    # Test setup
    if not test_setup(sdk_root, avd_name):
        print("\n⚠️  Setup completed but some tests failed")
        print("You may need to troubleshoot manually")
    
    # Success!
    print_header("Setup Complete! 🎉")
    print("Next steps:")
    print(f"  1. Run an analysis:")
    print(f"     python cli.py analyze /path/to/app.apk")
    print(f"\n  2. The emulator will start automatically")
    print(f"     (First boot: ~45s, subsequent boots with snapshot: ~15s)")
    print(f"\n  3. Results will be saved to: scanned_results/")
    print(f"\nConfiguration:")
    print(f"  • SDK: {sdk_root}")
    print(f"  • AVD: {avd_name}")
    print(f"  • Frida: {frida_server_path}")
    print("\nFor MITM proxy (optional):")
    print("  pip install mitmproxy")
    print("  python cli.py analyze app.apk --mitm-proxy")
    print()
    
    return 0

if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n\nSetup interrupted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n✗ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
