"""
Logcat Collector - Monitors Android system logs for security-relevant behaviors
Phase 2-Light: System-level monitoring via logcat
"""
import subprocess
import re
import json
import logging
import time
from pathlib import Path
from typing import Dict, Any, List, Set
from threading import Thread, Event
from queue import Queue
from datetime import datetime

logger = logging.getLogger(__name__)


class LogcatCollector:
    """
    Monitors Android system logs (logcat) to detect behaviors not visible to Frida
    
    Captures:
    - Permission requests (runtime permissions)
    - Intent broadcasts (system events)
    - Service starts/stops
    - ContentProvider queries
    - Native crashes
    - Network state changes
    - Location/Camera/Microphone access
    """
    
    def __init__(self, device_serial: str, adb_path: str, output_dir: str):
        """
        Initialize logcat collector
        
        Args:
            device_serial: Android device serial
            adb_path: Path to adb executable
            output_dir: Directory to store logs and analysis
        """
        self.device_serial = device_serial
        self.adb = adb_path
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Monitoring state
        self.monitoring = False
        self.stop_event = Event()  # Clean shutdown signal
        self.monitor_thread = None
        self.log_queue = Queue()
        self.process = None
        self.start_time = None  # Track when actual monitoring starts
        self.warmup_duration = 45  # Ignore first 45s (UIAutomator2 setup noise)
        
        # Pattern matching for security behaviors
        self.patterns = {
            'permission_request': re.compile(r'(PermissionChecker|PermissionManager).*?(uid=\d+|permission=[\w.]+)', re.IGNORECASE),
            'intent_broadcast': re.compile(r'(BroadcastQueue|ActivityManager).*?Intent.*?act=([\w.]+)', re.IGNORECASE),
            'service_start': re.compile(r'ActivityManager.*?(Start|stop).*?service.*?{([^}]+)}', re.IGNORECASE),
            'content_query': re.compile(r'ContentProvider.*?query.*?uri=([^\s]+)', re.IGNORECASE),
            'native_crash': re.compile(r'DEBUG.*?(signal|fault|SIGSEGV|SIGABRT)', re.IGNORECASE),
            'network_change': re.compile(r'ConnectivityService.*?(NetworkInfo|connect)', re.IGNORECASE),
            'location_access': re.compile(r'(LocationManager|FusedLocation).*?(request|getLastKnownLocation)', re.IGNORECASE),
            'camera_access': re.compile(r'Camera.*?(open|connect|start)', re.IGNORECASE),
            'microphone_access': re.compile(r'AudioRecord.*?(start|recording)', re.IGNORECASE),
            'file_access': re.compile(r'(open|read|write).*?(/sdcard|/data/data)', re.IGNORECASE),
            'root_detection': re.compile(r'(su |/system/xbin/su|Superuser|root)', re.IGNORECASE),
            'process_exec': re.compile(r'(exec|Runtime\.exec|ProcessBuilder)', re.IGNORECASE),
        }
        
        # Findings storage
        self.findings = {
            'permissions_requested': set(),
            'intents_broadcasted': set(),
            'services_started': set(),
            'content_queries': set(),
            'native_crashes': [],
            'network_events': [],
            'location_accesses': [],
            'camera_accesses': [],
            'microphone_accesses': [],
            'file_accesses': set(),
            'root_detections': [],
            'process_execs': [],
            'suspicious_behaviors': []
        }
        
        # Raw logs buffer (last 1000 lines)
        self.raw_logs = []
        self.max_raw_logs = 1000
        
        logger.info(f"LogcatCollector initialized, output dir: {output_dir}")
    
    def start_monitoring(self, package_name: str):
        """
        Start background logcat monitoring
        
        Args:
            package_name: Package name to monitor (used for filtering)
        """
        if self.monitoring:
            logger.warning("Logcat monitoring already running")
            return
        
        self.package_name = package_name
        
        # Clear existing logs
        try:
            subprocess.run(
                [self.adb, "-s", self.device_serial, "logcat", "-c"],
                timeout=5,
                capture_output=True
            )
        except Exception as e:
            logger.warning(f"Failed to clear logcat: {e}")
        
        logger.info(f"Starting logcat monitoring for {package_name}...")
        
        self.monitoring = True
        self.stop_event.clear()  # Reset stop signal
        self.start_time = time.time()  # Track start time for filtering
        self.monitor_thread = Thread(target=self._monitor_logs, daemon=False)  # Non-daemon for clean shutdown
        self.monitor_thread.start()
        
        logger.info("✓ Logcat monitoring active (45s warmup period to filter setup noise)")
    
    def _monitor_logs(self):
        """Background thread that reads logcat continuously"""
        try:
            # Start logcat process
            self.process = subprocess.Popen(
                [self.adb, "-s", self.device_serial, "logcat", "-v", "time"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )
            
            logger.debug("Logcat process started")
            
            lines_processed = 0
            
            while self.monitoring and not self.stop_event.is_set() and self.process:
                try:
                    line = self.process.stdout.readline()
                    
                    if not line:
                        break
                    
                    # Filter: only package-related logs + system-level security logs
                    if self._is_relevant_log(line):
                        # Store raw log
                        self.raw_logs.append(line.strip())
                        if len(self.raw_logs) > self.max_raw_logs:
                            self.raw_logs.pop(0)
                        
                        # Analyze for security patterns
                        self._analyze_log_line(line)
                        
                        lines_processed += 1
                        
                        if lines_processed % 100 == 0:
                            logger.debug(f"Processed {lines_processed} log lines")
                
                except Exception as e:
                    if self.monitoring:  # Only log if we're still monitoring
                        logger.debug(f"Error reading log line: {e}")
                    break
            
            logger.debug(f"Logcat monitoring stopped, processed {lines_processed} lines")
            
        except Exception as e:
            logger.error(f"Logcat monitoring thread error: {e}")
        finally:
            if self.process:
                try:
                    self.process.kill()
                except:
                    pass
    
    def _is_relevant_log(self, line: str) -> bool:
        """
        Check if log line is relevant to our analysis
        
        Filters to:
        - Lines containing package name
        - System-level security events (permissions, intents, etc.)
        """
        if not line or len(line) < 10:
            return False
        
        # Always include if it contains our package name
        if self.package_name and self.package_name in line:
            return True
        
        # Include system-level security events
        security_keywords = [
            'Permission', 'Intent', 'Service', 'ContentProvider',
            'ActivityManager', 'BroadcastQueue', 'ConnectivityService',
            'LocationManager', 'Camera', 'AudioRecord', 'DEBUG',
            'su ', 'root', 'exec'
        ]
        
        return any(keyword in line for keyword in security_keywords)
    
    def _analyze_log_line(self, line: str):
        """
        Extract security-relevant information from log line
        
        Args:
            line: Single log line from logcat
        """
        # Skip noisy events during warmup period (UIAutomator2 setup)
        if self.start_time and (time.time() - self.start_time) < self.warmup_duration:
            # Only log high-severity events during warmup
            if any(keyword in line for keyword in ['crash', 'FATAL', 'native_crash']):
                pass  # Continue analysis for crashes
            else:
                return  # Skip other patterns during warmup
        
        # Whitelist: Ignore known system/testing processes
        whitelisted_processes = [
            'atx-agent', 'uiautomator', 'com.github.uiautomator',
            'com.android.shell', 'adbd', 'logd', 'system_server'
        ]
        
        if any(process in line for process in whitelisted_processes):
            # Only allow camera/microphone/root detection from whitelisted (suspicious!)
            if not any(keyword in line for keyword in ['Camera', 'AudioRecord', 'su ', 'root']):
                return
        
        # Check each pattern
        for pattern_name, pattern in self.patterns.items():
            match = pattern.search(line)
            
            if match:
                # Extract relevant data based on pattern type
                if pattern_name == 'permission_request':
                    # Extract permission name if possible
                    perm_match = re.search(r'permission=([\w.]+)', line)
                    if perm_match:
                        permission = perm_match.group(1)
                        self.findings['permissions_requested'].add(permission)
                        logger.debug(f"Permission detected: {permission}")
                
                elif pattern_name == 'intent_broadcast':
                    intent = match.group(2) if len(match.groups()) >= 2 else 'unknown'
                    self.findings['intents_broadcasted'].add(intent)
                    logger.debug(f"Intent broadcast detected: {intent}")
                
                elif pattern_name == 'service_start':
                    service_info = match.group(2) if len(match.groups()) >= 2 else line
                    self.findings['services_started'].add(service_info)
                    logger.debug(f"Service activity detected: {service_info[:100]}")
                
                elif pattern_name == 'content_query':
                    uri = match.group(1) if len(match.groups()) >= 1 else 'unknown'
                    self.findings['content_queries'].add(uri)
                    logger.debug(f"ContentProvider query detected: {uri}")
                
                elif pattern_name == 'native_crash':
                    self.findings['native_crashes'].append({
                        'timestamp': time.time(),
                        'log': line.strip()
                    })
                    logger.warning(f"Native crash detected!")
                
                elif pattern_name == 'network_change':
                    self.findings['network_events'].append({
                        'timestamp': time.time(),
                        'log': line.strip()
                    })
                
                elif pattern_name == 'location_access':
                    self.findings['location_accesses'].append({
                        'timestamp': time.time(),
                        'log': line.strip()
                    })
                    logger.debug("Location access detected")
                
                elif pattern_name == 'camera_access':
                    self.findings['camera_accesses'].append({
                        'timestamp': time.time(),
                        'log': line.strip()
                    })
                    logger.info("📷 Camera access detected!")
                
                elif pattern_name == 'microphone_access':
                    self.findings['microphone_accesses'].append({
                        'timestamp': time.time(),
                        'log': line.strip()
                    })
                    logger.info("🎤 Microphone access detected!")
                
                elif pattern_name == 'file_access':
                    file_path = match.group(2) if len(match.groups()) >= 2 else 'unknown'
                    self.findings['file_accesses'].add(file_path)
                
                elif pattern_name == 'root_detection':
                    self.findings['root_detections'].append({
                        'timestamp': time.time(),
                        'log': line.strip()
                    })
                    logger.info("🔐 Root detection attempt!")
                
                elif pattern_name == 'process_exec':
                    self.findings['process_execs'].append({
                        'timestamp': time.time(),
                        'log': line.strip()
                    })
                    logger.info("⚙️  Process execution detected!")
    
    def stop_monitoring(self) -> Dict[str, Any]:
        """
        Stop monitoring and generate analysis report
        
        Returns:
            Dictionary with all findings
        """
        logger.info("Stopping logcat monitoring...")
        
        self.monitoring = False
        self.stop_event.set()  # Signal thread to stop
        
        # Wait for thread to finish (with timeout)
        if self.monitor_thread and self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=5)
            if self.monitor_thread.is_alive():
                logger.warning("Logcat thread did not stop cleanly within timeout")
        
        # Kill process if still running
        if self.process:
            try:
                self.process.kill()
                self.process.wait(timeout=2)
            except:
                pass
        
        # Convert sets to lists for JSON serialization
        report = {
            'package_name': self.package_name,
            'timestamp': datetime.now().isoformat(),
            'summary': {
                'permissions_requested': len(self.findings['permissions_requested']),
                'intents_broadcasted': len(self.findings['intents_broadcasted']),
                'services_started': len(self.findings['services_started']),
                'content_queries': len(self.findings['content_queries']),
                'native_crashes': len(self.findings['native_crashes']),
                'location_accesses': len(self.findings['location_accesses']),
                'camera_accesses': len(self.findings['camera_accesses']),
                'microphone_accesses': len(self.findings['microphone_accesses']),
                'root_detections': len(self.findings['root_detections']),
                'process_execs': len(self.findings['process_execs']),
            },
            'details': {
                'permissions_requested': sorted(list(self.findings['permissions_requested'])),
                'intents_broadcasted': sorted(list(self.findings['intents_broadcasted'])),
                'services_started': sorted(list(self.findings['services_started']))[:50],  # Limit
                'content_queries': sorted(list(self.findings['content_queries']))[:50],
                'native_crashes': self.findings['native_crashes'],
                'network_events': self.findings['network_events'][:20],
                'location_accesses': self.findings['location_accesses'][:20],
                'camera_accesses': self.findings['camera_accesses'],
                'microphone_accesses': self.findings['microphone_accesses'],
                'file_accesses': sorted(list(self.findings['file_accesses']))[:100],
                'root_detections': self.findings['root_detections'],
                'process_execs': self.findings['process_execs'],
            }
        }
        
        # Save detailed report
        report_file = self.output_dir / "logcat_analysis.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        # Save raw logs
        raw_log_file = self.output_dir / "logcat_raw.log"
        with open(raw_log_file, 'w') as f:
            f.write('\n'.join(self.raw_logs))
        
        logger.info(f"✓ Logcat analysis complete:")
        logger.info(f"  - Permissions: {report['summary']['permissions_requested']}")
        logger.info(f"  - Intents: {report['summary']['intents_broadcasted']}")
        logger.info(f"  - Services: {report['summary']['services_started']}")
        logger.info(f"  - Camera access: {report['summary']['camera_accesses']}")
        logger.info(f"  - Microphone access: {report['summary']['microphone_accesses']}")
        logger.info(f"  - Report saved: {report_file}")
        
        return report
