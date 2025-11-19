"""
Emulator Manager - Controls Android emulator lifecycle
Handles starting, stopping, snapshots, and health monitoring
"""
import subprocess
import time
import os
import logging
from typing import Optional, Dict, List
from pathlib import Path
import psutil

logger = logging.getLogger(__name__)


class EmulatorManager:
    """
    Manages Android Virtual Device (AVD) emulator instances for dynamic analysis
    """
    
    def __init__(self, android_sdk_root: Optional[str] = None):
        """
        Initialize emulator manager
        
        Args:
            android_sdk_root: Path to Android SDK (auto-detects if None)
        """
        self.android_sdk_root = android_sdk_root or os.environ.get(
            'ANDROID_SDK_ROOT',
            os.path.join(Path.home(), 'Android', 'Sdk')
        )
        
        self.emulator_bin = os.path.join(self.android_sdk_root, 'emulator', 'emulator')
        self.adb_bin = os.path.join(self.android_sdk_root, 'platform-tools', 'adb')
        
        self.current_emulator_process: Optional[subprocess.Popen] = None
        self.emulator_serial: Optional[str] = None
        self._emulator_log_file = None
        
        # Validate SDK installation
        if not os.path.exists(self.emulator_bin):
            raise RuntimeError(f"Android SDK not found at {self.android_sdk_root}")
        
        logger.info(f"EmulatorManager initialized with SDK: {self.android_sdk_root}")
    
    def list_avds(self) -> List[str]:
        """
        List all available Android Virtual Devices
        
        Returns:
            List of AVD names
        """
        try:
            result = subprocess.run(
                [self.emulator_bin, "-list-avds"],
                capture_output=True,
                text=True,
                timeout=10
            )
            avds = [line.strip() for line in result.stdout.split('\n') if line.strip()]
            logger.info(f"Found {len(avds)} AVDs: {avds}")
            return avds
        except Exception as e:
            logger.error(f"Failed to list AVDs: {e}")
            return []
    
    def start_emulator(self, 
                      avd_name: str = None,
                      headless: bool = True,
                      snapshot_name: str = None,
                      port: int = 5554,
                      timeout: int = 600) -> bool:
        """
        Start an emulator instance
        
        Args:
            avd_name: Name of the AVD to start
            headless: Run without GUI (recommended for automation)
            snapshot_name: Load specific snapshot state
            port: Emulator port (default 5554)
            timeout: Boot timeout in seconds
            
        Returns:
            True if started and booted successfully
        """
        if self.current_emulator_process:
            logger.warning("Emulator already running")
            return True
        
        # Check KVM availability for x86_64 emulators
        kvm_available = os.path.exists('/dev/kvm')
        
        if not kvm_available:
            logger.error("=" * 80)
            logger.error("KVM (hardware acceleration) is required for Android emulator!")
            logger.error("Please enable KVM with these commands:")
            logger.error("  sudo modprobe kvm")
            logger.error("  sudo modprobe kvm-amd  # or kvm-intel for Intel CPUs")
            logger.error("  sudo usermod -aG kvm $USER")
            logger.error("  sudo chmod 666 /dev/kvm")
            logger.error("=" * 80)
            return False
        
        # Build command
        cmd = [
            self.emulator_bin,
            "-avd", avd_name,
            "-port", str(port),
            "-no-boot-anim",  # Faster boot
            "-no-audio",      # No audio output
            "-memory", "2048", # 2GB RAM for better performance with KVM
            "-cores", "4",     # 4 CPU cores for better performance
            "-gpu", "swiftshader_indirect",  # Software rendering for headless
            "-partition-size", "2048",
            "-writable-system",  # CRITICAL: Allow Frida to run as root
        ]
        
        if headless:
            cmd.append("-no-window")
        
        if snapshot_name:
            cmd.extend(["-snapshot", snapshot_name])
        else:
            cmd.append("-no-snapshot-save")
        
        logger.info(f"Starting emulator: {' '.join(cmd)}")

        try:
            # Cleanup any stale emulator/qemu processes and adb state first
            try:
                killed_count = 0
                # kill common qemu/emulator processes (including zombies)
                for p in psutil.process_iter(attrs=['pid', 'name', 'cmdline', 'status']):
                    name = p.info.get('name', '') or ''
                    cmdline = ' '.join(p.info.get('cmdline') or [])
                    status = p.info.get('status', '')
                    
                    if 'qemu-system' in name or 'qemu-system' in cmdline or ('emulator' in name and 'qemu' in cmdline):
                        pid = p.info.get('pid')
                        logger.info(f"Killing stale emulator process {pid} ({name}, status={status})")
                        try:
                            p.kill()  # SIGKILL
                            p.wait(timeout=2)  # Wait for process to actually die
                            killed_count += 1
                        except (psutil.NoSuchProcess, psutil.TimeoutExpired):
                            pass
                
                if killed_count > 0:
                    logger.info(f"✓ Cleaned up {killed_count} stale emulator process(es)")
                    time.sleep(2)  # Give system time to clean up
            except Exception as e:
                logger.debug(f'Error during process cleanup: {e}')

            # Restart adb server to ensure clean device list
            try:
                subprocess.run([self.adb_bin, 'kill-server'], capture_output=True, timeout=5)
                time.sleep(1)
                subprocess.run([self.adb_bin, 'start-server'], capture_output=True, timeout=5)
                time.sleep(1)
            except Exception as e:
                logger.warning(f"Could not restart adb server cleanly: {e}")

            # Prepare a log file to capture emulator stdout/stderr for diagnostics
            logs_dir = os.path.join(os.getcwd(), 'logs')
            os.makedirs(logs_dir, exist_ok=True)
            emu_log = os.path.join(logs_dir, f"emulator_{avd_name}_{port}.log")
            self._emulator_log_file = open(emu_log, 'ab', buffering=0)  # Unbuffered write

            # Start emulator process and keep handle
            # NOTE: We do NOT use preexec_fn=os.setsid as it can create orphan/zombie processes
            # Instead we manage cleanup explicitly in stop_emulator()
            self.current_emulator_process = subprocess.Popen(
                cmd,
                stdout=self._emulator_log_file,
                stderr=subprocess.STDOUT,
                close_fds=False  # CRITICAL: Keep file descriptors open for emulator
            )

            self.emulator_serial = f"emulator-{port}"

            # Wait for boot
            if self._wait_for_boot(timeout=timeout):
                logger.info(f"✓ Emulator started successfully: {self.emulator_serial}")
                return True
            else:
                logger.error("Emulator failed to boot within timeout")
                # dump tail of emulator log for diagnosis
                try:
                    with open(emu_log, 'rb') as rf:
                        rf.seek(0, os.SEEK_END)
                        size = rf.tell()
                        tail = 8192 if size > 8192 else size
                        rf.seek(-tail, os.SEEK_END)
                        logger.error("Emulator log tail:\n" + rf.read().decode(errors='ignore'))
                except Exception:
                    logger.debug('Could not read emulator log')

                self.stop_emulator()
                return False

        except Exception as e:
            logger.error(f"Failed to start emulator: {e}")
            return False
    
    def _wait_for_boot(self, timeout: int = 600) -> bool:
        """
        Wait for emulator to fully boot
        
        Args:
            timeout: Maximum wait time in seconds
            
        Returns:
            True if booted successfully
        """
        logger.info("Waiting for emulator to boot...")
        start_time = time.time()
        last_status_time = start_time
        
        seen_device = False
        # First, wait for device to be online according to adb
        attempts = 0
        while time.time() - start_time < timeout:
            attempts += 1
            
            # Every 10 seconds, log progress and try to reconnect adb
            if time.time() - last_status_time >= 10:
                elapsed = int(time.time() - start_time)
                logger.info(f"Still waiting for emulator... ({elapsed}s elapsed, attempt #{attempts})")
                last_status_time = time.time()
                
                # Try to reconnect adb to the emulator port
                try:
                    subprocess.run(
                        [self.adb_bin, "connect", f"127.0.0.1:{5555}"],  # 5555 is adb port for 5554 console
                        capture_output=True,
                        timeout=3
                    )
                except Exception:
                    pass
            
            try:
                result = subprocess.run(
                    [self.adb_bin, "devices"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                out = result.stdout.strip()
                logger.debug(f"adb devices output: {out}")
                for line in out.splitlines()[1:]:
                    if not line.strip():
                        continue
                    parts = line.split()
                    if parts[0].strip() == self.emulator_serial or parts[0].startswith("emulator-"):
                        self.emulator_serial = parts[0].strip()  # Update with actual serial
                        status = parts[1] if len(parts) > 1 else 'unknown'
                        
                        # Only break if device is in 'device' state, not 'offline' or 'unauthorized'
                        if status == 'device':
                            seen_device = True
                            logger.info(f"✓ Emulator device online: {self.emulator_serial}")
                            break
                        else:
                            logger.debug(f"Emulator {self.emulator_serial} status: {status} (waiting for 'device')")
                        break  # Break inner loop but continue outer loop
                
                if seen_device:
                    break
            except Exception as e:
                logger.debug(f"adb devices check failed: {e}")
            
            # Check if emulator process is still alive
            if self.current_emulator_process and self.current_emulator_process.poll() is not None:
                logger.error(f"Emulator process died with exit code: {self.current_emulator_process.returncode}")
                return False
            
            time.sleep(2)  # Wait 2 seconds between checks

        if not seen_device:
            logger.error("Emulator device did not appear in adb device list")
            logger.error("This usually means the emulator failed to start or adb cannot connect")
            if self.current_emulator_process and self.current_emulator_process.poll() is not None:
                logger.error(f"Emulator process exit code: {self.current_emulator_process.returncode}")
            return False

        # Then wait for sys.boot_completed == 1
        while time.time() - start_time < timeout:
            try:
                result = subprocess.run(
                    [self.adb_bin, "-s", self.emulator_serial, "shell", "getprop", "sys.boot_completed"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                val = result.stdout.strip()
                logger.debug(f"sys.boot_completed: '{val}'")
                if val == "1":
                    # Wait a bit more for system stability
                    time.sleep(3)
                    # Verify package manager is ready
                    result = subprocess.run(
                        [self.adb_bin, "-s", self.emulator_serial, "shell", "pm", "list", "packages"],
                        capture_output=True,
                        text=True,
                        timeout=10
                    )
                    if result.returncode == 0:
                        logger.info("✓ Emulator fully booted and ready")
                        return True
                    else:
                        logger.debug(f"pm list packages returned code {result.returncode}")
            except subprocess.TimeoutExpired:
                logger.debug("adb shell getprop timed out")
            except Exception as e:
                logger.debug(f"Error while waiting for boot: {e}")

            time.sleep(2)

        logger.error("Timeout waiting for emulator to finish boot")
        return False
    
    def stop_emulator(self) -> bool:
        """
        Stop the running emulator with multiple fallback methods
        
        Returns:
            True if stopped successfully
        """
        # Also attempt to stop any emulator even if we don't have a local process handle
        if not self.current_emulator_process:
            logger.info("No tracked emulator process; attempting best-effort cleanup")
            try:
                # Try to kill any emulator via ADB
                subprocess.run([self.adb_bin, '-e', 'emu', 'kill'], capture_output=True, timeout=5)
                time.sleep(1)
            except Exception:
                pass
            
            # Force kill all emulator processes
            try:
                import psutil
                for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                    try:
                        name = proc.info.get('name', '')
                        cmdline = ' '.join(proc.info.get('cmdline') or [])
                        if 'qemu-system' in name or 'qemu-system' in cmdline or ('emulator' in name and 'avd' in cmdline.lower()):
                            logger.info(f"Force killing emulator: PID {proc.info['pid']}")
                            proc.kill()
                            proc.wait(timeout=2)
                    except:
                        pass
            except:
                pass
            
            try:
                subprocess.run([self.adb_bin, 'kill-server'], capture_output=True, timeout=5)
            except Exception:
                pass
            return True
        
        try:
            logger.info("Stopping emulator...")
            
            # Try graceful shutdown first via ADB
            try:
                subprocess.run(
                    [self.adb_bin, "-s", self.emulator_serial, "emu", "kill"],
                    timeout=10,
                    capture_output=True
                )
            except Exception:
                logger.debug("adb emu kill failed or timed out")

            # Wait for process to end
            try:
                self.current_emulator_process.wait(timeout=15)
                logger.info("✓ Emulator stopped gracefully")
            except Exception:
                # Force kill if graceful shutdown failed
                logger.warning("Graceful shutdown failed, force killing emulator")
                try:
                    # Use SIGKILL to ensure it dies
                    self.current_emulator_process.kill()
                    self.current_emulator_process.wait(timeout=5)
                    logger.info("✓ Emulator force killed")
                except Exception:
                    logger.warning("Failed to kill via process handle, trying psutil")
                    # Last resort: use psutil to kill entire process tree
                    try:
                        import psutil
                        parent = psutil.Process(self.current_emulator_process.pid)
                        children = parent.children(recursive=True)
                        for child in children:
                            child.kill()
                        parent.kill()
                        psutil.wait_procs([parent] + children, timeout=5)
                        logger.info("✓ Emulator process tree killed")
                    except Exception as e:
                        logger.error(f"Failed to kill emulator process tree: {e}")
            
        except (subprocess.TimeoutExpired, subprocess.SubprocessError):
            # Force kill if graceful shutdown failed
            logger.warning("Graceful shutdown failed, force killing emulator")
            self.current_emulator_process.kill()
            self.current_emulator_process.wait()
            logger.info("✓ Emulator force killed")
        
        finally:
            # Close log file handle if open
            if hasattr(self, '_emulator_log_file') and self._emulator_log_file:
                try:
                    self._emulator_log_file.close()
                    self._emulator_log_file = None
                except Exception:
                    pass
            
            # Also kill adb server to clear state
            try:
                subprocess.run([self.adb_bin, 'kill-server'], capture_output=True, timeout=5)
            except Exception:
                pass
            self.current_emulator_process = None
            self.emulator_serial = None
        
        return True
    
    def snapshot_exists(self, avd_name: str, snapshot_name: str) -> bool:
        """
        Check if a snapshot exists for the given AVD
        
        Args:
            avd_name: Name of the AVD
            snapshot_name: Name of the snapshot to check
            
        Returns:
            True if snapshot exists
        """
        try:
            # Snapshots are stored in ~/.android/avd/<avd_name>.avd/snapshots/<snapshot_name>/
            avd_dir = Path.home() / '.android' / 'avd' / f'{avd_name}.avd'
            snapshot_dir = avd_dir / 'snapshots' / snapshot_name
            
            exists = snapshot_dir.exists() and (snapshot_dir / 'snapshot.pb').exists()
            if exists:
                logger.debug(f"✓ Snapshot '{snapshot_name}' exists for AVD '{avd_name}'")
            else:
                logger.debug(f"✗ Snapshot '{snapshot_name}' not found for AVD '{avd_name}'")
            return exists
        except Exception as e:
            logger.warning(f"Error checking snapshot existence: {e}")
            return False
    
    def create_snapshot(self, snapshot_name: str) -> bool:
        """
        Create a snapshot of current emulator state
        
        Args:
            snapshot_name: Name for the snapshot
            
        Returns:
            True if snapshot created successfully
        """
        if not self.emulator_serial:
            logger.error("No emulator running")
            return False
        
        try:
            result = subprocess.run(
                [self.adb_bin, "-s", self.emulator_serial, "emu", 
                 "avd", "snapshot", "save", snapshot_name],
                check=True,
                timeout=60,
                capture_output=True
            )
            logger.info(f"✓ Snapshot '{snapshot_name}' created")
            return True
        except Exception as e:
            logger.error(f"Failed to create snapshot: {e}")
            return False
    
    def restore_snapshot(self, snapshot_name: str) -> bool:
        """
        Restore emulator to a previous snapshot
        
        Args:
            snapshot_name: Name of snapshot to restore
            
        Returns:
            True if restored successfully
        """
        if not self.emulator_serial:
            logger.error("No emulator running")
            return False
        
        try:
            result = subprocess.run(
                [self.adb_bin, "-s", self.emulator_serial, "emu",
                 "avd", "snapshot", "load", snapshot_name],
                check=True,
                timeout=90,
                capture_output=True
            )
            logger.info(f"✓ Snapshot '{snapshot_name}' restored")
            
            # Wait for emulator to stabilize after restore
            time.sleep(10)
            return True
        except Exception as e:
            logger.error(f"Failed to restore snapshot: {e}")
            return False
    
    def get_emulator_status(self) -> Dict[str, any]:
        """
        Get current emulator status and information
        
        Returns:
            Dictionary with emulator status details
        """
        if not self.emulator_serial:
            return {"running": False}
        
        try:
            # Get device properties
            result = subprocess.run(
                [self.adb_bin, "-s", self.emulator_serial, "shell", "getprop"],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            props = {}
            for line in result.stdout.split('\n'):
                if ':' in line and '[' in line:
                    parts = line.split(':', 1)
                    if len(parts) == 2:
                        key = parts[0].strip('[] ')
                        value = parts[1].strip('[] ')
                        props[key] = value
            
            return {
                "running": True,
                "serial": self.emulator_serial,
                "android_version": props.get('ro.build.version.release', 'Unknown'),
                "api_level": props.get('ro.build.version.sdk', 'Unknown'),
                "device_model": props.get('ro.product.model', 'Unknown'),
                "abi": props.get('ro.product.cpu.abi', 'Unknown'),
                "brand": props.get('ro.product.brand', 'Unknown'),
            }
            
        except Exception as e:
            logger.error(f"Failed to get emulator status: {e}")
            return {"running": False, "error": str(e)}
    
    def is_healthy(self) -> bool:
        """
        Check if emulator is healthy and responsive
        
        Returns:
            True if emulator is responding correctly
        """
        if not self.emulator_serial:
            return False
        
        try:
            # Test basic shell command
            result = subprocess.run(
                [self.adb_bin, "-s", self.emulator_serial, "shell", "echo", "test"],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode != 0:
                return False
            
            # Test package manager
            result = subprocess.run(
                [self.adb_bin, "-s", self.emulator_serial, "shell", "pm", "list", "packages", "-l", "1"],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            return result.returncode == 0
            
        except Exception as e:
            logger.error(f"Health check failed: {e}")
            return False
    
    def install_apk(self, apk_path: str) -> tuple[bool, Optional[str]]:
        """
        Install APK on emulator
        
        Args:
            apk_path: Path to APK file
            
        Returns:
            Tuple of (success, package_name)
        """
        if not self.emulator_serial:
            logger.error("No emulator running")
            return False, None
        
        if not os.path.exists(apk_path):
            logger.error(f"APK not found: {apk_path}")
            return False, None
        
        try:
            # Install APK
            # Check APK size to adjust timeout
            apk_size_mb = os.path.getsize(apk_path) / (1024 * 1024)
            install_timeout = 60 if apk_size_mb < 50 else 180  # 3 minutes for large APKs (50MB+)
            
            logger.info(f"Installing APK: {apk_path} ({apk_size_mb:.1f}MB, timeout={install_timeout}s)")
            result = subprocess.run(
                [self.adb_bin, "-s", self.emulator_serial, "install", "-r", "-t", apk_path],
                capture_output=True,
                text=True,
                timeout=install_timeout
            )
            
            if result.returncode != 0 or "Failure" in result.stdout:
                error_msg = result.stdout.strip() + result.stderr.strip()
                logger.error(f"APK installation failed: {error_msg}")
                
                # Parse common failure reasons and provide helpful messages
                if "INSTALL_FAILED_OLDER_SDK" in error_msg:
                    logger.error("❌ App requires newer Android version than emulator provides")
                    logger.error("   Solution: App needs Android API > 30, but emulator is API 30")
                elif "INSTALL_FAILED_NO_MATCHING_ABIS" in error_msg:
                    logger.error("❌ App architecture mismatch (wrong CPU type)")
                    logger.error("   Solution: App is for ARM but emulator is x86_64")
                elif "INSTALL_FAILED_INVALID_APK" in error_msg:
                    logger.error("❌ APK file is corrupted or invalid")
                elif "INSTALL_FAILED_UPDATE_INCOMPATIBLE" in error_msg:
                    logger.error("❌ Previous version exists with different signature")
                    logger.error("   Solution: Uninstall previous version first")
                elif "INSTALL_FAILED_INSUFFICIENT_STORAGE" in error_msg:
                    logger.error("❌ Not enough storage space on emulator")
                elif "INSTALL_PARSE_FAILED_NOT_APK" in error_msg:
                    logger.error("❌ File is not a valid APK")
                else:
                    logger.error(f"   Full error: {error_msg[:200]}")
                
                return False, None
            
            # Get package name using aapt
            aapt_bin = os.path.join(self.android_sdk_root, 'build-tools', '**', 'aapt')
            
            # Find aapt (try multiple locations)
            import glob
            aapt_paths = glob.glob(aapt_bin, recursive=True)
            if aapt_paths:
                result = subprocess.run(
                    [aapt_paths[0], "dump", "badging", apk_path],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                
                for line in result.stdout.split('\n'):
                    if line.startswith("package: name="):
                        package_name = line.split("'")[1]
                        logger.info(f"✓ APK installed: {package_name}")
                        return True, package_name
            
            # Fallback: try using androguard
            try:
                from androguard.core.apk import APK
                a = APK(apk_path)
                package_name = a.get_package()
                logger.info(f"✓ APK installed: {package_name}")
                return True, package_name
            except:
                pass
            
            logger.warning("APK installed but couldn't determine package name")
            return True, None
            
        except Exception as e:
            logger.error(f"Failed to install APK: {e}")
            return False, None
    
    def uninstall_app(self, package_name: str) -> bool:
        """
        Uninstall app from emulator
        
        Args:
            package_name: Android package name
            
        Returns:
            True if uninstalled successfully
        """
        if not self.emulator_serial:
            return False
        
        try:
            result = subprocess.run(
                [self.adb_bin, "-s", self.emulator_serial, "uninstall", package_name],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                logger.info(f"✓ Uninstalled: {package_name}")
                return True
            else:
                logger.warning(f"Failed to uninstall {package_name}: {result.stdout}")
                return False
                
        except Exception as e:
            logger.error(f"Error uninstalling app: {e}")
            return False
    
    def __enter__(self):
        """Context manager entry"""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - cleanup"""
        self.stop_emulator()
