"""
Dynamic Analysis Orchestrator - Main coordinator for dynamic analysis
"""
import time
import logging
import subprocess
import re
import os
from pathlib import Path
from typing import Dict, Any, Optional
from datetime import datetime

from core.emulator_manager import EmulatorManager
from instrumentation.frida_manager import FridaManager
from collectors.api_collector import APICollector
from collectors.network_collector import NetworkCollector
# UIAutomator2 removed - using pure ADB explorer only
from collectors.adb_ui_explorer import ADBUIExplorer  # Pure ADB UI exploration
from collectors.logcat_collector import LogcatCollector  # Phase 2
from collectors.https_collector import HTTPSCollector  # Phase 2.5

logger = logging.getLogger(__name__)


class DynamicAnalysisOrchestrator:
    """
    Orchestrates the entire dynamic analysis pipeline
    """
    
    def __init__(self, 
                 avd_name: str,
                 output_dir: str,
                 android_sdk_root: str = None,
                 adb_path: str = "adb",
                 emulator_path: str = "emulator",
                 frida_server_path: str = None):
        """
        Initialize orchestrator
        
        Args:
            avd_name: Android Virtual Device name
            output_dir: Base output directory for analysis results
            android_sdk_root: Path to Android SDK (or set ANDROID_SDK_ROOT env var)
            adb_path: Path to adb executable
            emulator_path: Path to emulator executable
            frida_server_path: Path to frida-server binary
        """
        self.avd_name = avd_name
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        self.android_sdk_root = android_sdk_root
        self.adb = adb_path
        self.emulator_path = emulator_path
        self.frida_server_path = frida_server_path
        
        self.emulator_manager: Optional[EmulatorManager] = None
        self.frida_manager: Optional[FridaManager] = None
        self.api_collector: Optional[APICollector] = None
        self.network_collector: Optional[NetworkCollector] = None
        self.https_collector: Optional[HTTPSCollector] = None  # Phase 2.5
        self.adb_explorer: Optional[ADBUIExplorer] = None  # Pure ADB UI exploration
        self.logcat_collector: Optional[LogcatCollector] = None  # Phase 2
        
        logger.info(f"DynamicAnalysisOrchestrator initialized for AVD: {avd_name}")
    
    def _detect_apk_sdk_requirements(self, apk_path: str) -> Dict[str, int]:
        """
        Detect APK's SDK version requirements
        
        Args:
            apk_path: Path to APK file
            
        Returns:
            Dictionary with minSdkVersion, targetSdkVersion, maxSdkVersion
        """
        try:
            # Try using androguard first (most reliable)
            try:
                from androguard.core.apk import APK
                apk = APK(apk_path)
                min_sdk = apk.get_min_sdk_version()
                target_sdk = apk.get_target_sdk_version()
                max_sdk = apk.get_max_sdk_version()
                
                logger.info(f"📱 APK SDK requirements: minSdk={min_sdk}, targetSdk={target_sdk}, maxSdk={max_sdk}")
                return {
                    'minSdkVersion': int(min_sdk) if min_sdk else 1,
                    'targetSdkVersion': int(target_sdk) if target_sdk else 30,
                    'maxSdkVersion': int(max_sdk) if max_sdk else 9999
                }
            except ImportError:
                logger.warning("androguard not available, falling back to aapt")
            
            # Fallback: Use aapt
            import glob
            aapt_bin = Path(self.android_sdk_root or '/home/mhy/Android/Sdk') / 'build-tools' / '**' / 'aapt'
            aapt_paths = glob.glob(str(aapt_bin), recursive=True)
            
            if aapt_paths:
                result = subprocess.run(
                    [aapt_paths[0], "dump", "badging", apk_path],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                
                min_sdk = 1
                target_sdk = 30
                max_sdk = 9999
                
                for line in result.stdout.split('\n'):
                    if 'sdkVersion' in line or 'targetSdkVersion' in line:
                        # Parse: sdkVersion:'21' or targetSdkVersion:'30'
                        min_match = re.search(r"sdkVersion:'(\d+)'", line)
                        target_match = re.search(r"targetSdkVersion:'(\d+)'", line)
                        max_match = re.search(r"maxSdkVersion:'(\d+)'", line)
                        
                        if min_match:
                            min_sdk = int(min_match.group(1))
                        if target_match:
                            target_sdk = int(target_match.group(1))
                        if max_match:
                            max_sdk = int(max_match.group(1))
                
                logger.info(f"📱 APK SDK requirements: minSdk={min_sdk}, targetSdk={target_sdk}, maxSdk={max_sdk}")
                return {
                    'minSdkVersion': min_sdk,
                    'targetSdkVersion': target_sdk,
                    'maxSdkVersion': max_sdk
                }
        except Exception as e:
            logger.warning(f"Could not detect SDK requirements: {e}")
        
        # Default: assume modern app
        return {
            'minSdkVersion': 21,
            'targetSdkVersion': 30,
            'maxSdkVersion': 9999
        }
    
    def _select_compatible_avd(self, sdk_requirements: Dict[str, int]) -> str:
        """
        Select the best AVD based on app's SDK requirements
        
        Args:
            sdk_requirements: Dict with minSdkVersion, targetSdkVersion, maxSdkVersion
            
        Returns:
            AVD name to use
        """
        target_sdk = sdk_requirements['targetSdkVersion']
        min_sdk = sdk_requirements['minSdkVersion']
        max_sdk = sdk_requirements['maxSdkVersion']
        
        # Map target SDK to Android version and preferred AVD
        # This allows testing old apps on appropriate Android versions
        if target_sdk <= 22:
            # Very old app (Android 5.1 or lower)
            logger.warning("="*70)
            logger.warning(f"⚠️  COMPATIBILITY ISSUE DETECTED")
            logger.warning("="*70)
            logger.warning(f"📱 App targets OLD Android: API {target_sdk} (Android 5.1 or lower)")
            logger.warning(f"🖥️  Current emulator: API 30 (Android 11)")
            logger.warning("")
            logger.warning("❌ This combination is KNOWN TO FAIL")
            logger.warning("   Apps with targetSdk <= 22 often crash on Android 11+ due to:")
            logger.warning("   • Strict permission model changes")
            logger.warning("   • Deprecated APIs removed")
            logger.warning("   • Security policy changes")
            logger.warning("")
            logger.warning("✅ SOLUTION: Create a lower API level AVD")
            logger.warning("")
            logger.warning("   Option 1: API 22 (Android 5.1) - Best match for this app")
            logger.warning(f"   $ avdmanager create avd -n Pixel_5_API_22 -k 'system-images;android-22;google_apis;x86_64'")
            logger.warning("")
            logger.warning("   Option 2: API 25 (Android 7.1) - Good balance")
            logger.warning(f"   $ avdmanager create avd -n Pixel_5_API_25 -k 'system-images;android-25;google_apis;x86_64'")
            logger.warning("")
            logger.warning("   Then run: python cli.py analyze app.apk --avd Pixel_5_API_22")
            logger.warning("="*70)
            logger.warning("")
            logger.warning("⚠️  Continuing anyway - expect analysis to FAIL")
            logger.warning("")
            return self.avd_name  # Use default for now, but warn user
        
        elif target_sdk <= 25:
            # Old app (Android 7.1 or lower)
            logger.warning(f"⚠️  App targets older Android (API {target_sdk})")
            logger.warning("   May have compatibility issues on API 30")
            logger.warning(f"   Recommendation: Create API 25 AVD if this fails")
            return self.avd_name
        
        else:
            # Modern app, current AVD is fine
            logger.info(f"✓ App compatible with current AVD (API 30)")
            return self.avd_name
    
    def analyze_apk(self, 
                   apk_path: str,
                   analysis_duration: int = 60,
                   spawn_mode: bool = True,
                   create_snapshot: bool = True,
                   enable_ui_automation: bool = True,
                   enable_logcat: bool = True,
                   enable_https_interception: bool = True,
                   ui_exploration_duration: int = 180,
                   enable_mitm: bool = False,
                   proxy_host: str = '127.0.0.1',
                   proxy_port: int = 8080) -> Dict[str, Any]:
        """
        Perform complete dynamic analysis of an APK (Phase 2.5 with Hybrid HTTPS Interception)
        
        Args:
            apk_path: Path to APK file
            analysis_duration: How long to run analysis (seconds) - used if UI automation disabled
            spawn_mode: If True, spawn app with Frida. If False, attach to running app
            create_snapshot: Create clean snapshot before analysis
            enable_ui_automation: Enable UIAutomator2-based UI exploration (Phase 2)
            enable_logcat: Enable system log monitoring (Phase 2)
            enable_https_interception: Enable HTTPS traffic decryption (Phase 2.5, no mitmproxy!)
            ui_exploration_duration: How long to explore UI (seconds, default 180=3min)
            enable_mitm: Enable MITM mode for Cronet/gRPC apps (activates SSL unpinning)
            proxy_host: Proxy host address for MITM mode (default: 127.0.0.1)
            proxy_port: Proxy port for MITM mode (default: 8080)
            
        Returns:
            Dictionary with analysis results and file paths
        """
        apk_path = Path(apk_path)
        if not apk_path.exists():
            raise FileNotFoundError(f"APK not found: {apk_path}")
        
        # Detect APK SDK requirements and select compatible AVD
        logger.info("🔍 Analyzing APK compatibility...")
        sdk_requirements = self._detect_apk_sdk_requirements(str(apk_path))
        compatible_avd = self._select_compatible_avd(sdk_requirements)
        
        # Update AVD name if different from default
        if compatible_avd != self.avd_name:
            logger.info(f"📱 Switching to compatible AVD: {compatible_avd}")
            self.avd_name = compatible_avd
        
        # Create analysis-specific output directory
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        analysis_dir = self.output_dir / f"analysis_{apk_path.stem}_{timestamp}"
        analysis_dir.mkdir(parents=True, exist_ok=True)
        
        logger.info(f"=" * 60)
        logger.info(f"Starting dynamic analysis of: {apk_path.name}")
        logger.info(f"Output directory: {analysis_dir}")
        logger.info(f"=" * 60)
        
        results = {
            'apk_path': str(apk_path),
            'timestamp': timestamp,
            'output_dir': str(analysis_dir),
            'success': False,
            'error': None
        }
        
        package_name = None  # Initialize package_name variable
        
        try:
            # Step 1: Start emulator (with auto-snapshot optimization!)
            logger.info("\n[1/9] Starting Android emulator...")
            self.emulator_manager = EmulatorManager(
                android_sdk_root=self.android_sdk_root
            )
            
            # 🚀 AUTO-SNAPSHOT FEATURE: Use clean snapshot for 3x faster boot!
            snapshot_name = "matrisks_clean_boot"  # Consistent snapshot name
            use_snapshot = self.emulator_manager.snapshot_exists(self.avd_name, snapshot_name)
            
            if use_snapshot:
                logger.info(f"⚡ Loading clean snapshot '{snapshot_name}' (3x faster boot!)...")
                if not self.emulator_manager.start_emulator(
                    avd_name=self.avd_name,
                    snapshot_name=snapshot_name
                ):
                    logger.warning("Failed to load snapshot, booting normally...")
                    # Fallback to normal boot
                    if not self.emulator_manager.start_emulator(avd_name=self.avd_name):
                        raise RuntimeError("Failed to start emulator")
            else:
                logger.info("📸 First-time boot - will create clean snapshot for future use...")
                if not self.emulator_manager.start_emulator(avd_name=self.avd_name):
                    raise RuntimeError("Failed to start emulator")
            
            device_serial = self.emulator_manager.emulator_serial
            logger.info(f"✓ Emulator running: {device_serial}")
            
            # Step 2: Create auto-snapshot if this is first boot (or manual snapshot if requested)
            if not use_snapshot:
                logger.info(f"\n[2/9] Creating '{snapshot_name}' for 3x faster future boots...")
                if self.emulator_manager.create_snapshot(snapshot_name):
                    logger.info(f"✓ Auto-snapshot created! Next boot will be 3x faster (15s vs 45s)")
                    results['snapshot_created'] = True
                else:
                    logger.warning("⚠️  Failed to create auto-snapshot (not critical)")
            elif create_snapshot:
                logger.info("\n[2/9] Creating custom snapshot...")
                custom_snapshot = f"clean_{timestamp}"
                if self.emulator_manager.create_snapshot(custom_snapshot):
                    logger.info(f"✓ Custom snapshot created: {custom_snapshot}")
                    results['snapshot_name'] = custom_snapshot
            else:
                logger.info("\n[2/9] Using existing clean snapshot (boot optimization active)")
            
            # Step 3: Setup Frida
            logger.info("\n[3/9] Setting up Frida instrumentation...")
            self.frida_manager = FridaManager(
                device_serial=device_serial,
                adb_path=self.adb
            )
            
            if self.frida_server_path:
                if not self.frida_manager.setup_frida_server(self.frida_server_path):
                    logger.warning("Frida server setup failed, trying to connect anyway...")
            
            if not self.frida_manager.connect():
                raise RuntimeError("Failed to connect to Frida")
            
            logger.info("✓ Frida connected")
            
            # Step 4: Install APK
            logger.info(f"\n[4/9] Installing APK: {apk_path.name}")
            success, package_name = self.emulator_manager.install_apk(str(apk_path))
            
            if not success or not package_name:
                raise RuntimeError(f"Failed to install APK or get package name")
            
            logger.info(f"✓ APK installed: {package_name}")
            results['package_name'] = package_name
            
            # Step 5: Initialize collectors
            logger.info("\n[5/9] Initializing data collectors...")
            self.api_collector = APICollector(str(analysis_dir))
            self.network_collector = NetworkCollector(str(analysis_dir))
            
            # Phase 2.5: Initialize HTTPS collector
            if enable_https_interception:
                self.https_collector = HTTPSCollector(str(analysis_dir))
                self.api_collector.set_https_collector(self.https_collector)
                logger.info("✓ HTTPS interception enabled (no mitmproxy needed!)")
            
            logger.info("✓ Collectors initialized")
            
            # Step 6: Attach Frida and load hooks
            logger.info(f"\n[6/9] Instrumenting app with Frida...")
            
            if spawn_mode:
                logger.info(f"Spawning {package_name} with instrumentation...")
                if not self.frida_manager.spawn_and_attach(package_name):
                    raise RuntimeError("Failed to spawn and attach")
            else:
                logger.info(f"Waiting for {package_name} to start...")
                logger.info("Please launch the app manually...")
                time.sleep(5)
                
                if not self.frida_manager.attach_to_app(package_name):
                    raise RuntimeError("Failed to attach to app")
            
            # Load hook script (Phase 2.5: Use enhanced script with HTTPS interception)
            hooks_dir = Path(__file__).parent.parent / "instrumentation" / "hooks"
            
            if enable_https_interception:
                api_monitor_script = hooks_dir / "enhanced_api_monitor.js"
                logger.info("Loading enhanced hooks with HTTPS interception...")
            else:
                api_monitor_script = hooks_dir / "api_monitor.js"
                logger.info("Loading standard API hooks...")
            
            if not api_monitor_script.exists():
                raise FileNotFoundError(f"Hook script not found: {api_monitor_script}")
            
            # Try to load script with retry
            script_loaded = self.frida_manager.load_script(
                str(api_monitor_script),
                message_handler=self.api_collector.handle_message
            )
            
            if not script_loaded:
                logger.warning("Script loading failed - app may have crashed on startup")
                logger.info("Trying to re-spawn and inject earlier...")
                
                # Detach and try again with attach mode (launch first, then inject)
                try:
                    self.frida_manager.detach()
                except:
                    pass
                
                # Use ADB to start the app and keep it running
                subprocess.run([
                    self.adb, "-s", device_serial, "shell", "am", "start",
                    "-W", "-n", f"{package_name}/.MainActivity"
                ], capture_output=True)
                
                time.sleep(3)
                
                # Now attach to the running process
                if not self.frida_manager.attach_to_app(package_name):
                    raise RuntimeError("Failed to load Frida script and re-attach failed")
                
                # Try loading script again
                if not self.frida_manager.load_script(
                    str(api_monitor_script),
                    message_handler=self.api_collector.handle_message
                ):
                    raise RuntimeError("Failed to load Frida script after retry")
            
            logger.info("✓ Hooks loaded and active")
            
            # Send configuration to Frida script (Phase 2.5: Hybrid HTTPS capture)
            if enable_mitm:
                logger.info(f"🔓 MITM mode enabled - SSL unpinning active (proxy: {proxy_host}:{proxy_port})")
            
            config_message = {
                'enable_mitm': enable_mitm,
                'proxy_host': proxy_host,
                'proxy_port': proxy_port
            }
            self.frida_manager.send_config(config_message)
            
            # Resume app if spawned
            if spawn_mode:
                if not self.frida_manager.resume_app():
                    logger.warning("Failed to resume app")
            
            # Step 6.5: Start Logcat monitoring (Phase 2)
            if enable_logcat:
                logger.info("\n[6.5/9] Starting system log monitoring...")
                self.logcat_collector = LogcatCollector(device_serial, self.adb, str(analysis_dir))
                self.logcat_collector.start_monitoring(package_name)
                logger.info("✓ Logcat monitoring active")
            
            # Step 7: Run analysis - UI Automation or Passive Monitoring
            if enable_ui_automation:
                logger.info(f"\n[7/9] Starting UI exploration (Pure ADB mode)...")
                logger.info(f"Duration: {ui_exploration_duration}s")
                logger.info("App will be automatically explored to trigger behaviors")
                
                # Use pure ADB explorer (more reliable, no UIAutomator2 issues)
                try:
                    logger.info("Using ADB UI Explorer (reliable, no UIAutomator2 dependency)")
                    adb_explorer = ADBUIExplorer(
                        device_serial=device_serial,
                        output_dir=str(analysis_dir),
                        adb_path=self.emulator_manager.adb_bin
                    )
                    ui_results = adb_explorer.explore_app(
                        package_name=package_name,
                        duration=ui_exploration_duration
                    )
                    results['ui_exploration'] = ui_results
                    logger.info("✓ UI exploration complete (ADB mode)")
                    
                except Exception as e:
                    logger.error(f"ADB UI exploration failed: {e}")
                    logger.info("Falling back to passive monitoring...")
                    # Continue with passive monitoring
                    time.sleep(ui_exploration_duration)
                    results['ui_exploration'] = {
                        'total_actions': 0,
                        'activities_explored': 0,
                        'elements_clicked': 0,
                        'screenshots': 0,
                        'error': str(e)
                    }
                
            else:
                # Fallback to passive monitoring (Phase 1 behavior)
                logger.info(f"\n[7/9] Running passive analysis for {analysis_duration} seconds...")
                logger.info("App is now running with instrumentation active")
                logger.info("Collecting API calls and behavior data...")
                
                start_time = time.time()
                elapsed = 0
                
                while elapsed < analysis_duration:
                    time.sleep(5)
                    elapsed = time.time() - start_time
                    
                    stats = self.api_collector.get_statistics()
                    logger.info(f"Progress: {int(elapsed)}/{analysis_duration}s - "
                              f"Calls collected: {stats['total_calls']}")
                
                logger.info("✓ Analysis complete")
            
            # Step 8: Stop logcat and collect results (Phase 2)
            if enable_logcat and self.logcat_collector:
                logger.info("\n[8/9] Collecting system log analysis...")
                logcat_results = self.logcat_collector.stop_monitoring()
                results['logcat_findings'] = logcat_results
                logger.info("✓ Logcat analysis complete")
            
            # Step 9: Generate reports
            logger.info("\n[9/9] Generating comprehensive reports...")
            
            # Save API calls
            api_file = self.api_collector.save_to_file()
            results['api_calls_file'] = str(api_file)
            
            # Save network traffic
            network_file = self.network_collector.save_to_file()
            results['network_file'] = str(network_file)
            
            # Save HTTPS traffic (Phase 2.5)
            if enable_https_interception and self.https_collector:
                https_file = self.https_collector.save_to_file()
                results['https_traffic_file'] = str(https_file)
                results['https_statistics'] = self.https_collector.get_statistics()
                results['https_sensitive_data'] = self.https_collector.get_sensitive_data()
                logger.info(f"✓ HTTPS traffic saved: {len(self.https_collector.get_requests())} requests, "
                          f"{len(self.https_collector.get_responses())} responses")
            
            # Get statistics
            results['statistics'] = self.api_collector.get_statistics()
            results['sensitive_behaviors'] = self.api_collector.get_sensitive_behaviors()
            results['network_statistics'] = self.network_collector.get_statistics()
            
            logger.info("✓ Reports generated")
            
            # Generate comprehensive reports (JSON, CSV, HTML)
            try:
                logger.info("\n📊 Generating comprehensive analysis reports...")
                from report_generator import DynamicReportGenerator
                report_gen = DynamicReportGenerator(analysis_dir)
                report_paths = report_gen.save_all_reports()
                results['comprehensive_reports'] = report_paths
                logger.info(f"✓ Comprehensive reports: JSON, CSV, HTML")
            except Exception as report_error:
                logger.warning(f"Failed to generate comprehensive reports: {report_error}")
            
            # Success!
            results['success'] = True
            logger.info("\n" + "=" * 60)
            phase_label = "Phase 2.5" if enable_https_interception else "Phase 2-Light"
            logger.info(f"Dynamic analysis completed successfully! ({phase_label})")
            logger.info(f"Total API calls: {results['statistics']['total_calls']}")
            
            # HTTPS statistics (Phase 2.5)
            if enable_https_interception and 'https_statistics' in results:
                https_stats = results['https_statistics']
                logger.info(f"HTTPS requests captured: {https_stats['total_requests']}")
                logger.info(f"HTTPS responses captured: {https_stats['total_responses']}")
                logger.info(f"Unique domains contacted: {https_stats['unique_domains']}")
                if results.get('https_sensitive_data'):
                    # Count total findings across all categories
                    sensitive_count = sum(len(findings) for findings in results['https_sensitive_data'].values())
                    logger.info(f"⚠️  Sensitive data detected: {sensitive_count} finding(s)")
            
            if enable_ui_automation and 'ui_exploration' in results:
                logger.info(f"UI actions taken: {results['ui_exploration']['total_actions']}")
            if enable_logcat and 'logcat_findings' in results:
                logger.info(f"Permissions detected: {results['logcat_findings']['summary']['permissions_requested']}")
                logger.info(f"Intents detected: {results['logcat_findings']['summary']['intents_broadcasted']}")
            logger.info(f"Output directory: {analysis_dir}")
            logger.info("=" * 60)
            
        except KeyboardInterrupt:
            logger.warning("\n⚠️  Analysis interrupted by user (Ctrl+C)!")
            logger.info("Saving partial results...")
            results['error'] = "Interrupted by user"
            results['partial'] = True
            
            # Save whatever we have so far
            try:
                if self.api_collector:
                    api_file = self.api_collector.save_to_file()
                    results['api_calls_file'] = str(api_file)
                    results['statistics'] = self.api_collector.get_statistics()
                
                if self.network_collector:
                    network_file = self.network_collector.save_to_file()
                    results['network_file'] = str(network_file)
                
                # Save HTTPS traffic (Phase 2.5)
                if enable_https_interception and self.https_collector:
                    https_file = self.https_collector.save_to_file()
                    results['https_traffic_file'] = str(https_file)
                    results['https_statistics'] = self.https_collector.get_statistics()
                    logger.info(f"✓ HTTPS traffic saved: {len(self.https_collector.get_requests())} requests")
                
                if enable_logcat and self.logcat_collector:
                    logger.info("Collecting partial logcat data...")
                    logcat_results = self.logcat_collector.stop_monitoring()
                    results['logcat_findings'] = logcat_results
                
                logger.info(f"✓ Partial results saved to: {analysis_dir}")
            except Exception as save_error:
                logger.error(f"Failed to save partial results: {save_error}")
            
            raise  # Re-raise KeyboardInterrupt for proper CLI handling
        
        except Exception as e:
            logger.error(f"\n❌ Analysis failed: {e}", exc_info=True)
            results['error'] = str(e)
        
        finally:
            # Cleanup - CRITICAL: Always runs regardless of success/failure
            logger.info("\nCleaning up...")
            
            # Frida cleanup
            if self.frida_manager:
                try:
                    logger.info("Detaching Frida...")
                    self.frida_manager.detach()
                except Exception as e:
                    logger.warning(f"Frida detach failed: {e}")
            
            # App uninstall
            if self.emulator_manager and package_name:
                try:
                    logger.info(f"Uninstalling {package_name}...")
                    self.emulator_manager.uninstall_app(package_name)
                except Exception as e:
                    logger.warning(f"App uninstall failed: {e}")
            
            # Emulator stop - MOST IMPORTANT
            if self.emulator_manager:
                try:
                    logger.info("Stopping emulator...")
                    if not self.emulator_manager.stop_emulator():
                        logger.warning("Emulator stop returned False, forcing cleanup...")
                        # Force kill any remaining processes
                        import psutil
                        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                            try:
                                name = proc.info.get('name', '')
                                cmdline = ' '.join(proc.info.get('cmdline') or [])
                                if 'qemu-system' in name or 'qemu-system' in cmdline or 'emulator' in name:
                                    logger.info(f"Force killing emulator: PID {proc.info['pid']}")
                                    proc.kill()
                            except:
                                pass
                except Exception as e:
                    logger.error(f"Emulator cleanup failed: {e}")
                    logger.info("Attempting force cleanup...")
                    # Last resort cleanup
                    try:
                        import psutil
                        for proc in psutil.process_iter(['pid', 'name']):
                            if 'qemu' in proc.info.get('name', '').lower() or 'emulator' in proc.info.get('name', '').lower():
                                proc.kill()
                    except:
                        pass
            
            logger.info("✓ Cleanup complete")
        
        return results
    
    def list_available_avds(self):
        """List available Android Virtual Devices"""
        temp_manager = EmulatorManager(
            android_sdk_root=self.android_sdk_root
        )
        return temp_manager.list_avds()
