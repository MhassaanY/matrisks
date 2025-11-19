"""
Frida Manager - Handles Frida server and script injection
Provides runtime instrumentation capabilities for Android apps
"""
import subprocess
import time
import logging
from typing import Optional, Callable, Dict, Any, List
from pathlib import Path
import json

try:
    import frida
except ImportError:
    print("Warning: Frida not installed. Run: pip install frida frida-tools")
    frida = None

logger = logging.getLogger(__name__)


class FridaManager:
    """
    Manages Frida instrumentation for dynamic analysis
    """
    
    def __init__(self, device_serial: str, adb_path: str = "adb"):
        """
        Initialize Frida manager
        
        Args:
            device_serial: ADB device serial (e.g., emulator-5554)
            adb_path: Path to adb executable
        """
        if frida is None:
            raise ImportError("Frida is not installed. Run: pip install frida frida-tools")
        
        self.device_serial = device_serial
        self.adb = adb_path
        self.device: Optional[frida.core.Device] = None
        self.session: Optional[frida.core.Session] = None
        self.script: Optional[frida.core.Script] = None
        self.collected_messages: List[Dict[str, Any]] = []
        
        logger.info(f"FridaManager initialized for device: {device_serial}")
    
    def setup_frida_server(self, frida_server_path: str) -> bool:
        """
        Push and start Frida server on device
        
        Args:
            frida_server_path: Local path to frida-server binary
            
        Returns:
            True if setup successful
        """
        try:
            logger.info("Setting up Frida server...")
            
            # Kill any existing frida-server
            subprocess.run(
                [self.adb, "-s", self.device_serial, "shell", "killall", "frida-server"],
                capture_output=True
            )
            time.sleep(1)
            
            # Push frida-server
            logger.info("Pushing frida-server to device...")
            result = subprocess.run(
                [self.adb, "-s", self.device_serial, 
                 "push", frida_server_path, "/data/local/tmp/frida-server"],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode != 0:
                logger.error(f"Failed to push frida-server: {result.stderr}")
                return False
            
            # Make executable
            subprocess.run(
                [self.adb, "-s", self.device_serial,
                 "shell", "chmod", "755", "/data/local/tmp/frida-server"],
                check=True
            )
            
            # Kill any existing frida-server first
            subprocess.run(
                [self.adb, "-s", self.device_serial, "shell", "su", "root", "killall", "frida-server"],
                capture_output=True
            )
            time.sleep(1)
            
            # Start frida-server in background AS ROOT (critical for injection)
            logger.info("Starting frida-server as root...")
            subprocess.Popen([
                self.adb, "-s", self.device_serial,
                "shell", "su", "root", "/data/local/tmp/frida-server", "&"
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            # Wait for server to start
            time.sleep(3)
            
            # Verify it's running
            result = subprocess.run(
                [self.adb, "-s", self.device_serial, "shell", "ps", "|", "grep", "frida-server"],
                capture_output=True,
                text=True
            )
            
            if "frida-server" in result.stdout:
                logger.info("✓ Frida server started successfully")
                return True
            else:
                logger.warning("Frida server may not be running properly")
                return False
            
        except Exception as e:
            logger.error(f"Failed to setup Frida server: {e}")
            return False
    
    def connect(self) -> bool:
        """
        Connect to Frida server on device
        
        Returns:
            True if connected successfully
        """
        try:
            # List all devices
            devices = frida.enumerate_devices()
            logger.info(f"Available Frida devices: {[(d.name, d.id, d.type) for d in devices]}")
            
            # Find our device by matching the serial in the device ID
            # STRICT matching: device.id must EXACTLY match or contain our emulator serial
            target_device = None
            for device in devices:
                # SKIP: local, remote, iOS devices explicitly
                if device.type in ['local', 'remote']:
                    logger.debug(f"Skipping {device.type} device: {device.name}")
                    continue
                
                # SKIP: iOS devices by name/id
                device_str = f"{device.name} {device.id}".lower()
                if 'ios' in device_str or 'iphone' in device_str or 'ipad' in device_str:
                    logger.debug(f"Skipping iOS device: {device.name} ({device.id})")
                    continue
                    
                # MATCH: Android emulator by serial in device.id
                if self.device_serial == device.id or self.device_serial in device.id:
                    target_device = device
                    logger.debug(f"Found matching device: {device.name} ({device.id})")
                    break
            
            if target_device:
                self.device = target_device
                logger.info(f"✓ Connected to Frida device: {self.device.name} ({self.device.id})")
                return True
            
            logger.error(f"Could not find Frida device for {self.device_serial}")
            logger.error(f"Available devices: {[(d.name, d.id) for d in devices]}")
            return False
            
        except Exception as e:
            logger.error(f"Failed to connect to Frida: {e}")
            return False
    
    def check_app_compatibility(self, package_name: str) -> Dict[str, Any]:
        """
        Check if app can run on the device (diagnostic method)
        
        Args:
            package_name: Package to check
            
        Returns:
            Compatibility info dict
        """
        info = {
            'package': package_name,
            'installed': False,
            'main_activity': None,
            'target_sdk': None,
            'min_sdk': None,
            'issues': []
        }
        
        try:
            # Check if installed
            result = subprocess.run(
                [self.adb, '-s', self.device_serial, 'shell', 'pm', 'list', 'packages', package_name],
                capture_output=True,
                text=True,
                timeout=5
            )
            info['installed'] = package_name in result.stdout
            
            if info['installed']:
                # Get package info
                result = subprocess.run(
                    [self.adb, '-s', self.device_serial, 'shell', 'dumpsys', 'package', package_name],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                output = result.stdout
                
                # Extract SDK versions
                import re
                target_match = re.search(r'targetSdk=(\d+)', output)
                min_match = re.search(r'minSdk=(\d+)', output)
                
                if target_match:
                    info['target_sdk'] = int(target_match.group(1))
                if min_match:
                    info['min_sdk'] = int(min_match.group(1))
                
                # Check for potential issues
                if info['target_sdk'] and info['target_sdk'] < 23:
                    info['issues'].append(f"Old target SDK {info['target_sdk']} (may have permission issues on Android 11+)")
                    
        except Exception as e:
            logger.debug(f"Compatibility check failed: {e}")
            
        return info
    
    def attach_to_app(self, package_name: str) -> bool:
        """
        Attach Frida to a running app
        
        Args:
            package_name: Android package name
            
        Returns:
            True if attached successfully
        """
        if not self.device:
            logger.error("Not connected to device")
            return False
        
        try:
            logger.info(f"Attaching to {package_name}...")
            self.session = self.device.attach(package_name)
            logger.info(f"✓ Attached to {package_name}")
            return True
        except frida.ProcessNotFoundError:
            logger.error(f"Process not found: {package_name}. Is the app running?")
            return False
        except Exception as e:
            logger.error(f"Failed to attach to {package_name}: {e}")
            return False
    
    def grant_dangerous_permissions(self, package_name: str) -> int:
        """
        Grant all dangerous permissions to avoid runtime permission dialogs
        
        Args:
            package_name: Package name to grant permissions to
            
        Returns:
            Number of permissions granted successfully
        """
        dangerous_permissions = [
            'android.permission.READ_CALENDAR',
            'android.permission.WRITE_CALENDAR',
            'android.permission.CAMERA',
            'android.permission.READ_CONTACTS',
            'android.permission.WRITE_CONTACTS',
            'android.permission.GET_ACCOUNTS',
            'android.permission.ACCESS_FINE_LOCATION',
            'android.permission.ACCESS_COARSE_LOCATION',
            'android.permission.RECORD_AUDIO',
            'android.permission.READ_PHONE_STATE',
            'android.permission.READ_PHONE_NUMBERS',
            'android.permission.CALL_PHONE',
            'android.permission.READ_CALL_LOG',
            'android.permission.WRITE_CALL_LOG',
            'android.permission.ADD_VOICEMAIL',
            'android.permission.USE_SIP',
            'android.permission.PROCESS_OUTGOING_CALLS',
            'android.permission.BODY_SENSORS',
            'android.permission.SEND_SMS',
            'android.permission.RECEIVE_SMS',
            'android.permission.READ_SMS',
            'android.permission.RECEIVE_WAP_PUSH',
            'android.permission.RECEIVE_MMS',
            'android.permission.READ_EXTERNAL_STORAGE',
            'android.permission.WRITE_EXTERNAL_STORAGE',
            'android.permission.ACCESS_MEDIA_LOCATION'
        ]
        
        granted = 0
        logger.info(f"Granting dangerous permissions to {package_name}...")
        
        for perm in dangerous_permissions:
            try:
                result = subprocess.run(
                    [self.adb, '-s', self.device_serial, 'shell', 
                     'pm', 'grant', package_name, perm],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                
                if result.returncode == 0:
                    granted += 1
                    logger.debug(f"✓ Granted: {perm.split('.')[-1]}")
                else:
                    # Permission might not be requested by app, which is fine
                    logger.debug(f"  Skipped: {perm.split('.')[-1]} (not requested)")
                    
            except Exception as e:
                logger.debug(f"Failed to grant {perm}: {e}")
        
        logger.info(f"✓ Granted {granted}/{len(dangerous_permissions)} permissions")
        return granted
    
    def spawn_and_attach(self, package_name: str) -> bool:
        """
        Spawn app and attach Frida session
        
        Args:
            package_name: Android app package name
            
        Returns:
            True if spawned and attached successfully
        """
        try:
            logger.info(f"Spawning {package_name}...")
            
            # Run compatibility check
            compat = self.check_app_compatibility(package_name)
            if compat['issues']:
                logger.warning(f"Compatibility issues detected:")
                for issue in compat['issues']:
                    logger.warning(f"  - {issue}")
            
            # Grant dangerous permissions BEFORE launching to avoid dialogs
            self.grant_dangerous_permissions(package_name)
            time.sleep(1)
            
            # Method 1: Try direct Frida spawn (works on rooted with -writable-system)
            try:
                logger.info("Attempting Frida native spawn...")
                pid = self.device.spawn([package_name])
                logger.info(f"✓ App spawned with PID: {pid} (PAUSED - ready for pre-hooking)")
                
                # CRITICAL: Attach BEFORE resuming so hooks are active from first instruction
                self.session = self.device.attach(pid)
                logger.info(f"✓ Attached to process {pid}")
                
                # Store PID for later use
                self.spawned_pid = pid
                
                # NOTE: App is still PAUSED here - hooks will be loaded next
                # Then resume() will be called after script.load() in load_script()
                logger.info("⏸️  App paused, ready to load hooks before execution")
                
                return True
                
            except Exception as e:
                logger.warning(f"Frida native spawn failed: {e}")
                logger.info("Falling back to ADB launch + attach...")
            
            # Method 2: Launch via ADB then attach to running process
            # First kill any existing instance
            logger.info("Killing any existing app instance...")
            subprocess.run(
                [self.adb, '-s', self.device_serial, 'shell', 'am', 'force-stop', package_name],
                capture_output=True,
                timeout=5
            )
            time.sleep(2)
            
            logger.info("Launching app via ADB...")
            self._launch_via_adb(package_name)
            
            # Wait for process to start with better matching
            logger.info("Waiting for app process...")
            for attempt in range(20):  # Increased to 20 attempts (40 seconds total)
                time.sleep(2)  # Increased wait time
                
                try:
                    procs = self.device.enumerate_processes()
                    
                    # Find the target process with multiple matching strategies
                    for proc in procs:
                        proc_name = proc.name.lower()
                        pkg_lower = package_name.lower()
                        
                        # Try multiple matching strategies
                        if (proc_name == pkg_lower or  # Exact match
                            proc_name.startswith(pkg_lower) or  # Starts with
                            pkg_lower in proc_name or  # Contains
                            proc_name.split(':')[0] == pkg_lower):  # Match base package (before :)
                            
                            logger.info(f"Found process: {proc.name} (PID: {proc.pid})")
                            
                            try:
                                self.session = self.device.attach(proc.pid)
                                logger.info(f"✓ Attached to process {proc.pid}")
                                time.sleep(1)  # Give attachment time to stabilize
                                return True
                            except Exception as e:
                                logger.warning(f"Attach attempt failed: {e}")
                                continue
                    
                    logger.debug(f"Process not found yet (attempt {attempt+1}/20)")
                    
                    # Every 5 attempts, try relaunching the app
                    if attempt > 0 and attempt % 5 == 0:
                        logger.info("Relaunching app...")
                        subprocess.run(
                            [self.adb, '-s', self.device_serial, 'shell', 'am', 'force-stop', package_name],
                            capture_output=True,
                            timeout=10  # Increased timeout
                        )
                        time.sleep(2)
                        self._launch_via_adb(package_name)
                        
                except Exception as e:
                    logger.warning(f"Error during process enumeration: {e}")
            
            # Last resort: list all processes for debugging  
            logger.error(f"❌ Process {package_name} not found after 20 attempts (40 seconds)")
            logger.error("")
            logger.error("🔍 Possible causes:")
            logger.error("")
            logger.error("  1️⃣  APP CRASHES ON STARTUP")
            logger.error("     Check logcat for crash details:")
            logger.error(f"     adb -s {self.device_serial} logcat | grep -i crash")
            logger.error("")
            logger.error("  2️⃣  INCOMPATIBLE ANDROID VERSION")
            logger.error("     App may require different API level")
            logger.error(f"     Current emulator: API 30 (Android 11)")
            logger.error("     Try: Check app's minSdkVersion/targetSdkVersion")
            logger.error("")
            logger.error("  3️⃣  MISSING DEPENDENCIES")
            logger.error("     App needs Google Play Services, ARM libraries, etc.")
            logger.error("")
            logger.error("  4️⃣  ANTI-ANALYSIS DETECTION")
            logger.error("     App detected emulator or Frida")
            logger.error("")
            logger.error("📋 Debugging steps:")
            logger.error("  • Check logcat: adb logcat | grep -E 'AndroidRuntime|FATAL'")
            logger.error("  • Try manual install: adb install -r app.apk && adb shell am start -n <package>/<activity>")
            logger.error("  • Verify APK info: aapt dump badging app.apk | grep -E 'sdkVersion|package'")
            logger.error("")
            logger.error("Available processes (showing first 20):")
            try:
                procs = self.device.enumerate_processes()
                for proc in list(procs)[:20]:  # Show first 20 processes
                    logger.error(f"  - {proc.name} (PID: {proc.pid})")
            except Exception:
                pass
                
            return False
                
        except Exception as e:
            logger.error(f"Failed to spawn and attach: {e}")
            return False
    
    def resume_app(self) -> bool:
        """
        Resume a spawned app (must be called after spawn_and_attach)
        
        Returns:
            True if resumed successfully
        """
        if not self.device or not self.session:
            logger.error("No active session")
            return False
        
        try:
            # Get the PID from session
            pid = self.session._impl.pid
            
            # Try to resume (will fail if app is already running, which is OK)
            try:
                self.device.resume(pid)
                logger.info("✓ App resumed")
            except Exception as resume_err:
                # App might already be running (launched via ADB)
                logger.info("App already running (no resume needed)")
            
            return True
        except Exception as e:
            logger.error(f"Failed to resume app: {e}")
            return False
    
    def load_script(self, script_path: str, message_handler: Optional[Callable] = None) -> bool:
        """
        Load and inject Frida JavaScript hook script
        
        Args:
            script_path: Path to JavaScript hook script
            message_handler: Callback for script messages (optional)
            
        Returns:
            True if script loaded successfully
        """
        if not self.session:
            logger.error("No active session")
            return False
        
        try:
            # Read script
            with open(script_path, 'r') as f:
                script_code = f.read()
            
            logger.info(f"Loading script: {script_path}")
            
            # Give app time to stabilize after spawn/resume
            time.sleep(2)
            
            # Verify process is still alive before loading script
            try:
                # Try to enumerate processes to see if our process exists
                processes = self.device.enumerate_processes()
                pid = self.session._impl.pid
                process_alive = any(p.pid == pid for p in processes)
                if not process_alive:
                    logger.error(f"Process {pid} died before script could be loaded")
                    return False
            except:
                # If we can't check, proceed anyway
                pass
            
            # Create script with retry logic (app might be initializing)
            max_retries = 3
            for attempt in range(max_retries):
                try:
                    self.script = self.session.create_script(script_code)
                    
                    # Set message handler
                    if message_handler:
                        self.script.on('message', message_handler)
                    else:
                        self.script.on('message', self._default_message_handler)
                    
                    # Load script
                    self.script.load()
                    logger.info(f"✓ Script loaded successfully")
                    
                    # CRITICAL: If app was spawned (paused), resume it NOW with hooks active
                    if hasattr(self, 'spawned_pid') and self.spawned_pid:
                        logger.info(f"🚀 Resuming app PID {self.spawned_pid} with hooks pre-loaded")
                        time.sleep(0.5)  # Let hooks settle
                        self.device.resume(self.spawned_pid)
                        logger.info("✓ App resumed - hooks active from first instruction!")
                        self.spawned_pid = None  # Clear flag
                    
                    return True
                except Exception as retry_err:
                    if "closed" in str(retry_err).lower() or "detached" in str(retry_err).lower():
                        logger.error(f"App process terminated (attempt {attempt+1}/{max_retries})")
                        if attempt < max_retries - 1:
                            time.sleep(1)
                            continue
                    raise
            
            return False
            
        except Exception as e:
            logger.error(f"Failed to load script: {e}")
            return False
    
    def load_script_code(self, script_code: str, message_handler: Optional[Callable] = None) -> bool:
        """
        Load and inject Frida JavaScript code directly
        
        Args:
            script_code: JavaScript code to inject
            message_handler: Callback for script messages (optional)
            
        Returns:
            True if script loaded successfully
        """
        if not self.session:
            logger.error("No active session")
            return False
        
        try:
            logger.info("Loading script code...")
            
            # Create script
            self.script = self.session.create_script(script_code)
            
            # Set message handler
            if message_handler:
                self.script.on('message', message_handler)
            else:
                self.script.on('message', self._default_message_handler)
            
            # Load script
            self.script.load()
            logger.info("✓ Script code loaded successfully")
            
            # CRITICAL: If app was spawned (paused), resume it NOW with hooks active
            if hasattr(self, 'spawned_pid') and self.spawned_pid:
                logger.info(f"🚀 Resuming app PID {self.spawned_pid} with hooks pre-loaded")
                time.sleep(0.5)  # Let hooks settle
                self.device.resume(self.spawned_pid)
                logger.info("✓ App resumed - hooks active from first instruction!")
                self.spawned_pid = None  # Clear flag
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to load script code: {e}")
            return False
    
    def send_config(self, config: Dict[str, Any]) -> bool:
        """
        Send configuration message to loaded Frida script
        
        Args:
            config: Configuration dictionary to send
            
        Returns:
            True if message sent successfully
        """
        if not self.script:
            logger.warning("No active script to send config to")
            return False
        
        try:
            self.script.post({'type': 'config', 'payload': config})
            logger.debug(f"Configuration sent to script: {config}")
            return True
        except Exception as e:
            logger.error(f"Failed to send config to script: {e}")
            return False
    
    def _default_message_handler(self, message: Dict[str, Any], data: Optional[bytes]):
        """
        Default handler for Frida messages
        
        Args:
            message: Message dictionary from Frida
            data: Optional binary data
        """
        if message['type'] == 'send':
            payload = message.get('payload', {})
            self.collected_messages.append({
                'timestamp': time.time(),
                'type': 'send',
                'payload': payload
            })
            logger.debug(f"[Frida] {payload}")
            
        elif message['type'] == 'error':
            error_msg = {
                'timestamp': time.time(),
                'type': 'error',
                'stack': message.get('stack', ''),
                'description': message.get('description', '')
            }
            self.collected_messages.append(error_msg)
            logger.error(f"[Frida Error] {message.get('description', '')}")
            logger.error(f"Stack: {message.get('stack', '')}")
    
    def get_collected_messages(self) -> List[Dict[str, Any]]:
        """
        Get all messages collected from Frida scripts
        
        Returns:
            List of message dictionaries
        """
        return self.collected_messages.copy()
    
    def clear_messages(self):
        """Clear collected messages"""
        self.collected_messages.clear()
    
    def list_processes(self) -> List[Dict[str, Any]]:
        """
        List all running processes on device
        
        Returns:
            List of process dictionaries with name and pid
        """
        if not self.device:
            logger.error("Not connected to device")
            return []
        
        try:
            processes = self.device.enumerate_processes()
            return [{'name': p.name, 'pid': p.pid} for p in processes]
        except Exception as e:
            logger.error(f"Failed to list processes: {e}")
            return []
    
    def detach(self):
        """Detach from app and cleanup"""
        if self.script:
            try:
                self.script.unload()
                logger.info("✓ Script unloaded")
            except:
                pass
            self.script = None
        
        if self.session:
            try:
                self.session.detach()
                logger.info("✓ Detached from app")
            except:
                pass
            self.session = None
    
    def _launch_via_adb(self, package_name: str) -> bool:
        """Launch app via ADB activity manager"""
        try:
            # Get launchable activity
            result = subprocess.run(
                [self.adb, '-s', self.device_serial, 'shell', 'cmd', 'package', 'resolve-activity', 
                 '--brief', package_name],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            activity = None
            for line in result.stdout.splitlines():
                line = line.strip()
                if line and '/' in line and not line.startswith('priority'):
                    activity = line
                    break
            
            if not activity:
                logger.warning(f"No launchable activity found via resolve-activity, trying alternative methods")
                
                # Try to get main activity from package manager
                result = subprocess.run(
                    [self.adb, '-s', self.device_serial, 'shell', 'dumpsys', 'package', package_name],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                
                # Look for MAIN/LAUNCHER activity
                for line in result.stdout.splitlines():
                    if 'android.intent.action.MAIN' in line:
                        # Next line usually has the activity name
                        continue
                    if package_name in line and 'Activity' in line and '/' in line:
                        parts = line.split()
                        for part in parts:
                            if package_name in part and '/' in part:
                                activity = part
                                logger.info(f"Found activity via dumpsys: {activity}")
                                break
                        if activity:
                            break
                
                # If still no activity, use monkey to launch
                if not activity:
                    logger.info(f"Using monkey to launch {package_name}")
                    result = subprocess.run(
                        [self.adb, '-s', self.device_serial, 'shell', 'monkey', '-p', package_name, '-c', 
                         'android.intent.category.LAUNCHER', '1'],
                        capture_output=True,
                        text=True,
                        timeout=10
                    )
                    logger.info(f"Monkey output: {result.stdout[:200]}")
                    return True
            
            # Launch the activity
            logger.info(f"Launching activity: {activity}")
            result = subprocess.run(
                [self.adb, '-s', self.device_serial, 'shell', 'am', 'start', '-W', '-n', activity],
                capture_output=True,
                text=True,
                timeout=15
            )
            
            if result.returncode == 0:
                logger.info(f"Activity launched: {result.stdout[:200]}")
                return True
            else:
                logger.warning(f"Activity launch returned code {result.returncode}: {result.stderr[:200]}")
                # Try monkey as fallback
                logger.info("Trying monkey as fallback...")
                subprocess.run(
                    [self.adb, '-s', self.device_serial, 'shell', 'monkey', '-p', package_name, '-c', 
                     'android.intent.category.LAUNCHER', '1'],
                    capture_output=True,
                    timeout=10
                )
                return True
            
        except Exception as e:
            logger.error(f"Failed to launch via ADB: {e}")
            # Last resort: monkey
            try:
                logger.info("Using monkey as last resort...")
                subprocess.run(
                    [self.adb, '-s', self.device_serial, 'shell', 'monkey', '-p', package_name, '1'],
                    capture_output=True,
                    timeout=10
                )
                return True
            except Exception:
                return False
    
    def _launch_and_attach(self, package_name: str, script_source: str) -> bool:
        """
        Fallback: Launch app via ADB and attach to running process
        """
        try:
            # Kill any existing instance first
            subprocess.run(
                [self.adb, '-s', self.device_serial, 'shell', 'am', 'force-stop', package_name],
                capture_output=True,
                timeout=5
            )
            time.sleep(1)
            
            # Launch the app
            if not self._launch_via_adb(package_name):
                return False
            
            # Wait and find the process
            logger.info("Waiting for app process to start...")
            for attempt in range(15):  # Increased from 5 to 15 attempts
                time.sleep(1)
                
                # Enumerate all processes
                try:
                    processes = self.device.enumerate_processes()
                    
                    # Try to find by exact package name or partial match
                    target_proc = None
                    for proc in processes:
                        if package_name == proc.name or package_name in proc.name:
                            target_proc = proc
                            break
                    
                    if target_proc:
                        logger.info(f"Found process: {target_proc.name} (PID: {target_proc.pid})")
                        
                        # Attach to the process
                        self.session = self.device.attach(target_proc.pid)
                        logger.info(f"✓ Attached to PID {target_proc.pid}")
                        
                        # Load instrumentation
                        self.script = self.session.create_script(script_source)
                        self.script.on('message', self._on_message)
                        self.script.load()
                        logger.info("✓ Instrumentation script loaded")
                        
                        return True
                    else:
                        logger.debug(f"Attempt {attempt + 1}/15: Process not found yet...")
                        
                except Exception as attach_err:
                    logger.debug(f"Attach attempt {attempt + 1} failed: {attach_err}")
            
            logger.error(f"Process {package_name} not found after 15 attempts")
            return False
            
        except Exception as e:
            logger.error(f"Launch and attach failed: {e}")
            return False
    
    def __enter__(self):
        """Context manager entry"""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - cleanup"""
        self.detach()
