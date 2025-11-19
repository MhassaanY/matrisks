"""
Pure ADB-based UI Explorer - No UIAutomator2 dependency
Reliable alternative that works on all Android versions
"""
import subprocess
import time
import logging
import random
import re
import os
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, Any, List, Tuple, Optional
import json

logger = logging.getLogger(__name__)


class ADBUIExplorer:
    """
    UI exploration using pure ADB commands - no UIAutomator2 required
    More reliable but less intelligent than UIAutomator2
    """
    
    def __init__(self, device_serial: str, output_dir: str, adb_path: str = None):
        """
        Initialize ADB UI Explorer
        
        Args:
            device_serial: Android device serial (e.g., emulator-5554)
            output_dir: Directory to store screenshots and data
            adb_path: Full path to ADB binary (auto-detects if None)
        """
        self.device_serial = device_serial
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Get ADB path from SDK or use provided
        if adb_path:
            self.adb_bin = adb_path
        else:
            import os
            android_sdk = os.environ.get('ANDROID_SDK_ROOT', os.path.join(Path.home(), 'Android', 'Sdk'))
            self.adb_bin = os.path.join(android_sdk, 'platform-tools', 'adb')
            
        logger.debug(f"Using ADB: {self.adb_bin}")
        
        self.screenshots_dir = self.output_dir / "screenshots"
        self.screenshots_dir.mkdir(exist_ok=True)
        
        self.actions_taken: List[Dict[str, Any]] = []
        self.start_time = None
        
        # Get screen dimensions
        self.screen_width, self.screen_height = self._get_screen_dimensions()
        logger.info(f"ADB UI Explorer initialized: {self.screen_width}x{self.screen_height}")
    
    def _run_adb(self, command: str, timeout: int = 10) -> Tuple[bool, str]:
        """Run ADB command"""
        try:
            # Build command properly - handle shell commands with pipes
            if "shell" in command and ("|" in command or "grep" in command):
                # Use shell=True for complex shell commands
                full_cmd = f"{self.adb_bin} -s {self.device_serial} {command}"
                result = subprocess.run(
                    full_cmd,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=timeout
                )
            else:
                # Use safe list form for simple commands
                cmd_parts = [self.adb_bin, '-s', self.device_serial] + command.split()
                result = subprocess.run(
                    cmd_parts,
                    capture_output=True,
                    text=True,
                    timeout=timeout
                )
            return result.returncode == 0, result.stdout.strip()
        except Exception as e:
            logger.debug(f"ADB command failed: {e}")
            return False, str(e)
    
    def _get_screen_dimensions(self) -> Tuple[int, int]:
        """Get actual screen dimensions from device"""
        success, output = self._run_adb("shell wm size")
        if success and "Physical size:" in output:
            # Parse: Physical size: 1080x2340
            match = re.search(r'(\d+)x(\d+)', output)
            if match:
                width, height = int(match.group(1)), int(match.group(2))
                logger.info(f"Screen dimensions: {width}x{height}")
                return width, height
        
        # Fallback to common resolutions
        logger.warning("Could not detect screen size, using default 1080x2340")
        return 1080, 2340
    
    def _tap(self, x: int, y: int) -> bool:
        """Tap at coordinates"""
        success, _ = self._run_adb(f"shell input tap {x} {y}")
        if success:
            logger.debug(f"Tapped ({x}, {y})")
        return success
    
    def _swipe(self, x1: int, y1: int, x2: int, y2: int, duration: int = 300) -> bool:
        """Swipe gesture"""
        success, _ = self._run_adb(f"shell input swipe {x1} {y1} {x2} {y2} {duration}")
        if success:
            logger.debug(f"Swiped from ({x1},{y1}) to ({x2},{y2})")
        return success
    
    def _keyevent(self, keycode: int) -> bool:
        """Send key event"""
        success, _ = self._run_adb(f"shell input keyevent {keycode}")
        return success
    
    def _back(self) -> bool:
        """Press back button"""
        return self._keyevent(4)
    
    def _home(self) -> bool:
        """Press home button"""
        return self._keyevent(3)
    
    def _menu(self) -> bool:
        """Press menu button"""
        return self._keyevent(82)
    
    def _get_current_activity(self) -> str:
        """Get current foreground activity"""
        success, output = self._run_adb("shell dumpsys window | grep -E 'mCurrentFocus|mFocusedApp'")
        if success:
            # Parse activity name from output
            match = re.search(r'([a-z0-9.]+)/([a-z0-9.]+\.[A-Z][a-zA-Z0-9]*)', output, re.IGNORECASE)
            if match:
                return f"{match.group(1)}/{match.group(2)}"
        return "unknown"
    
    def _dump_ui_hierarchy(self) -> Optional[str]:
        """Dump current UI hierarchy to XML"""
        try:
            # Dump UI to device
            self._run_adb("shell uiautomator dump /sdcard/window_dump.xml", timeout=5)
            time.sleep(0.5)
            
            # Read XML content
            success, xml_content = self._run_adb("shell cat /sdcard/window_dump.xml", timeout=5)
            
            if success and xml_content and len(xml_content) > 100:
                return xml_content
            
            return None
        except Exception as e:
            logger.debug(f"UI dump failed: {e}")
            return None
    
    def _find_network_buttons(self) -> List[Dict[str, Any]]:
        """
        Find buttons that likely trigger network calls
        Looks for: Refresh, Load, Search, Login, Submit, Send, Get, Fetch, Update, Sync
        """
        xml_content = self._dump_ui_hierarchy()
        if not xml_content:
            return []
        
        buttons = []
        network_keywords = [
            'refresh', 'reload', 'load', 'search', 'login', 'signin', 'sign in',
            'submit', 'send', 'get', 'fetch', 'update', 'sync', 'download',
            'retrieve', 'connect', 'request', 'query', 'go', 'enter'
        ]
        
        try:
            root = ET.fromstring(xml_content)
            
            for node in root.iter('node'):
                # Check if clickable
                if node.get('clickable') != 'true':
                    continue
                
                # Get text and content-desc
                text = (node.get('text') or '').lower()
                desc = (node.get('content-desc') or '').lower()
                resource_id = (node.get('resource-id') or '').lower()
                class_name = node.get('class') or ''
                
                # Skip if empty
                if not text and not desc and not resource_id:
                    continue
                
                # Check for network keywords
                combined = f"{text} {desc} {resource_id}"
                if any(keyword in combined for keyword in network_keywords):
                    # Parse bounds: [x1,y1][x2,y2]
                    bounds_str = node.get('bounds', '')
                    match = re.findall(r'\[(\d+),(\d+)\]', bounds_str)
                    
                    if len(match) == 2:
                        x1, y1 = int(match[0][0]), int(match[0][1])
                        x2, y2 = int(match[1][0]), int(match[1][1])
                        center_x = (x1 + x2) // 2
                        center_y = (y1 + y2) // 2
                        
                        # Calculate priority (how likely this triggers network)
                        priority = 0
                        if 'refresh' in combined: priority += 10
                        if 'load' in combined: priority += 8
                        if 'search' in combined: priority += 7
                        if 'login' in combined: priority += 9
                        if 'get' in combined: priority += 6
                        if 'update' in combined: priority += 8
                        if 'sync' in combined: priority += 8
                        if 'button' in class_name.lower(): priority += 2
                        
                        buttons.append({
                            'text': text or desc or 'unlabeled',
                            'x': center_x,
                            'y': center_y,
                            'priority': priority,
                            'resource_id': resource_id
                        })
            
            # Sort by priority (highest first)
            buttons.sort(key=lambda b: b['priority'], reverse=True)
            
            if buttons:
                logger.info(f"Found {len(buttons)} potential network-trigger buttons")
                for btn in buttons[:3]:  # Log top 3
                    logger.info(f"  - '{btn['text']}' at ({btn['x']}, {btn['y']}) priority={btn['priority']}")
            
            return buttons
            
        except Exception as e:
            logger.debug(f"Button detection failed: {e}")
            return []
    
    def _take_screenshot(self, name: str) -> bool:
        """Take screenshot"""
        try:
            screenshot_path = self.screenshots_dir / f"{name}.png"
            # Use shell command to save to device, then pull
            temp_path = f"/sdcard/{name}.png"
            
            # Take screenshot on device
            self._run_adb(f"shell screencap -p {temp_path}", timeout=5)
            time.sleep(0.5)
            
            # Pull to host
            subprocess.run([
                self.adb_bin, "-s", self.device_serial, "pull", temp_path, str(screenshot_path)
            ], capture_output=True, timeout=10)
            
            # Cleanup device
            self._run_adb(f"shell rm {temp_path}", timeout=2)
            
            if screenshot_path.exists() and screenshot_path.stat().st_size > 1000:
                logger.debug(f"Screenshot: {name}.png ({screenshot_path.stat().st_size} bytes)")
                return True
            return False
        except Exception as e:
            logger.debug(f"Screenshot failed: {e}")
            return False
    
    def _random_tap_in_zone(self, zone: str) -> Tuple[int, int]:
        """
        Generate random tap coordinates in safe zones
        
        Zones: 'top', 'center', 'bottom', 'left', 'right'
        """
        margin = 100
        
        if zone == 'center':
            x = random.randint(self.screen_width // 4, 3 * self.screen_width // 4)
            y = random.randint(self.screen_height // 3, 2 * self.screen_height // 3)
        elif zone == 'top':
            x = random.randint(margin, self.screen_width - margin)
            y = random.randint(200, self.screen_height // 3)
        elif zone == 'bottom':
            x = random.randint(margin, self.screen_width - margin)
            y = random.randint(2 * self.screen_height // 3, self.screen_height - 200)
        elif zone == 'left':
            x = random.randint(margin, self.screen_width // 3)
            y = random.randint(self.screen_height // 3, 2 * self.screen_height // 3)
        elif zone == 'right':
            x = random.randint(2 * self.screen_width // 3, self.screen_width - margin)
            y = random.randint(self.screen_height // 3, 2 * self.screen_height // 3)
        else:
            # Full screen random
            x = random.randint(margin, self.screen_width - margin)
            y = random.randint(self.screen_height // 4, 3 * self.screen_height // 4)
        
        return x, y
    
    def explore_app(self, package_name: str, duration: int = 180) -> Dict[str, Any]:
        """
        Explore app using ADB commands
        
        Strategy:
        1. Random taps in different screen zones
        2. Swipe gestures (scroll, navigate)
        3. Back button navigation
        4. Handle common dialogs (Allow, OK, etc.)
        
        Args:
            package_name: Package to explore
            duration: Exploration duration in seconds
            
        Returns:
            Exploration statistics
        """
        self.start_time = time.time()
        action_count = 0
        screenshot_count = 0
        activities_seen = set()
        
        logger.info(f"Starting ADB UI exploration of {package_name} for {duration}s")
        logger.info("Using INTELLIGENT exploration: prioritizing network-trigger buttons")
        
        # Take initial screenshot
        if self._take_screenshot("initial"):
            screenshot_count += 1
            logger.info("✓ Initial screenshot captured")
        else:
            logger.warning("✗ Initial screenshot failed")
        
        iterations = 0
        network_buttons_clicked = 0
        last_button_scan = 0
        cached_buttons = []
        
        logger.info(f"Beginning exploration loop (target duration: {duration}s)")
        
        while time.time() - self.start_time < duration:
            iterations += 1
            elapsed = time.time() - self.start_time
            
            # Get current activity
            current_activity = self._get_current_activity()
            activities_seen.add(current_activity)
            logger.debug(f"Iteration {iterations}: Activity={current_activity}, Elapsed={elapsed:.1f}s")
            
            # Scan for network buttons every 10 seconds or on activity change
            if elapsed - last_button_scan > 10 or not cached_buttons:
                logger.debug("Scanning UI for network-trigger buttons...")
                cached_buttons = self._find_network_buttons()
                last_button_scan = elapsed
            
            # SMART STRATEGY: Prioritize network buttons over random exploration
            strategy = None
            action_type = None
            
            # 70% chance to tap network button if available
            if cached_buttons and random.random() < 0.7:
                # Try top 3 buttons in order of priority
                for btn in cached_buttons[:3]:
                    if btn['x'] > 0 and btn['y'] > 0:
                        strategy = 'tap_network_button'
                        action_success = self._tap(btn['x'], btn['y'])
                        action_type = f"tap_button[{btn['text']}]"
                        
                        if action_success:
                            network_buttons_clicked += 1
                            logger.info(f"✓ Tapped network button: '{btn['text']}' (priority={btn['priority']})")
                            # Remove clicked button from cache
                            cached_buttons.remove(btn)
                        break
            
            # If no network button clicked, use standard exploration
            if strategy is None:
                strategies = [
                    ('tap_center', 3),
                    ('tap_top', 2),
                    ('tap_bottom', 2),
                    ('swipe_up', 2),
                    ('swipe_down', 2),
                    ('swipe_left', 1),
                    ('swipe_right', 1),
                    ('back', 1),
                    ('menu', 1)
                ]
                
                # Weighted random choice
                strategy = random.choices(
                    [s[0] for s in strategies],
                    weights=[s[1] for s in strategies],
                    k=1
                )[0]
                
                logger.debug(f"Chosen strategy: {strategy}")
            
            # Execute strategy (if not already executed for smart button)
            if strategy != 'tap_network_button':
                action_success = False
                
                if strategy == 'tap_center':
                    x, y = self._random_tap_in_zone('center')
                    action_success = self._tap(x, y)
                    action_type = 'tap'
                    
                elif strategy == 'tap_top':
                    x, y = self._random_tap_in_zone('top')
                    action_success = self._tap(x, y)
                    action_type = 'tap'
                    
                elif strategy == 'tap_bottom':
                    x, y = self._random_tap_in_zone('bottom')
                    action_success = self._tap(x, y)
                    action_type = 'tap'
                    
                elif strategy == 'swipe_up':
                    x = self.screen_width // 2
                    action_success = self._swipe(x, self.screen_height - 300, x, 300)
                    action_type = 'swipe_up'
                    
                elif strategy == 'swipe_down':
                    x = self.screen_width // 2
                    action_success = self._swipe(x, 300, x, self.screen_height - 300)
                    action_type = 'swipe_down'
                    
                elif strategy == 'swipe_left':
                    y = self.screen_height // 2
                    action_success = self._swipe(self.screen_width - 200, y, 200, y)
                    action_type = 'swipe_left'
                    
                elif strategy == 'swipe_right':
                    y = self.screen_height // 2
                    action_success = self._swipe(200, y, self.screen_width - 200, y)
                    action_type = 'swipe_right'
                    
                elif strategy == 'back':
                    action_success = self._back()
                    action_type = 'back'
                    
                elif strategy == 'menu':
                    action_success = self._menu()
                    action_type = 'menu'
                
            # Handle smart button success (already executed above)
            if strategy == 'tap_network_button' and action_success:
                pass  # Already logged above
            
            if action_success:
                action_count += 1
                logger.info(f"✓ Action #{action_count}: {action_type} succeeded")
                self.actions_taken.append({
                    'action': action_type,
                    'timestamp': time.time(),
                    'elapsed': elapsed,
                    'activity': current_activity
                })
                
                # Wait for UI response
                time.sleep(1.5)
                
                # Take screenshot every 5 actions
                if action_count % 5 == 0:
                    if self._take_screenshot(f"screen_{action_count}"):
                        screenshot_count += 1
                        logger.info(f"✓ Screenshot #{screenshot_count} captured")
            else:
                logger.warning(f"✗ Action failed: {action_type}")
            
            # Small delay between actions
            time.sleep(0.5)
        
        # Final screenshot
        if self._take_screenshot("final"):
            screenshot_count += 1
            logger.info("✓ Final screenshot captured")
        
        logger.info(f"Exploration loop completed: {iterations} iterations, {action_count} successful actions")
        logger.info(f"Network buttons clicked: {network_buttons_clicked} (smart targeting)")
        
        # Generate report
        results = {
            'package_name': package_name,
            'total_actions': action_count,
            'activities_explored': len(activities_seen),
            'screenshots': screenshot_count,
            'duration': time.time() - self.start_time,
            'actions': self.actions_taken,
            'elements_clicked': action_count,  # For compatibility
            'network_buttons_clicked': network_buttons_clicked,
            'exploration_mode': 'intelligent'  # vs 'random'
        }
        
        # Save report
        report_file = self.output_dir / "ui_exploration.json"
        with open(report_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        logger.info(f"✓ ADB UI exploration complete:")
        logger.info(f"  - Total actions: {action_count}")
        logger.info(f"  - Activities explored: {len(activities_seen)}")
        logger.info(f"  - Screenshots: {screenshot_count}")
        logger.info(f"  - Report saved: {report_file}")
        
        return results
    
    def stop(self):
        """Cleanup"""
        logger.info("ADB UI Explorer stopped")
