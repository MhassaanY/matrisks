"""
API Call Collector - Collects and stores API monitoring data from Frida
"""
import json
import logging
from pathlib import Path
from typing import Dict, Any, List
from datetime import datetime
from collections import defaultdict

logger = logging.getLogger(__name__)


class APICollector:
    """
    Collects API call data from Frida hooks
    """
    
    def __init__(self, output_dir: str):
        """
        Initialize API collector
        
        Args:
            output_dir: Directory to store collected data
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # In-memory storage
        self.api_calls: List[Dict[str, Any]] = []
        self.statistics = defaultdict(int)
        self.start_time = datetime.now()
        
        # HTTPS collector reference (set by orchestrator)
        self.https_collector = None
        
        logger.info(f"APICollector initialized, output dir: {output_dir}")
    
    def set_https_collector(self, https_collector):
        """
        Set HTTPS collector reference for forwarding HTTPS messages
        
        Args:
            https_collector: HTTPSCollector instance
        """
        self.https_collector = https_collector
    
    def handle_message(self, message: Dict[str, Any], data: Any = None):
        """
        Handle incoming messages from Frida
        
        Args:
            message: Message dictionary from Frida
            data: Optional binary data
        """
        if message['type'] == 'send':
            payload = message.get('payload', {})
            
            # Check if it's an init complete message
            if payload.get('type') == 'init_complete':
                logger.info("Frida hooks initialized")
                logger.info(f"Hooked APIs: {payload.get('hooked_apis', {})}")
                
                # Handle Cronet detection (Phase 2.5: Hybrid approach)
                if payload.get('uses_cronet'):
                    logger.warning("⚠️  App uses Cronet (Chrome networking stack)")
                    logger.warning("⚠️  Traditional HTTPS hooks cannot capture request/response bodies")
                    if payload.get('ssl_unpinning_active'):
                        logger.info("✓ SSL unpinning active - MITM mode enabled")
                        logger.info("💡 Configure system to route traffic through mitmproxy for full capture")
                    else:
                        logger.warning("💡 Tip: Use --mitm-proxy flag to enable full HTTPS body capture for Cronet apps")
                else:
                    logger.info("✓ Standard TLS stack detected - full HTTPS capture available")
                
                return
            
            # Handle Cronet detection message
            if payload.get('type') == 'cronet_detected':
                logger.warning("=" * 60)
                logger.warning("CRONET DETECTED")
                logger.warning(f"Library: {payload.get('path', 'N/A')}")
                logger.warning("App uses gRPC/HTTP2 - requires MITM for full body capture")
                logger.warning("=" * 60)
                return
            
            # Handle gRPC detection message
            if payload.get('type') == 'grpc_detected':
                logger.info(f"gRPC library detected: {payload.get('path', 'N/A')}")
                return
            
            # Store API call
            category = payload.get('category', 'unknown')
            action = payload.get('action', 'unknown')
            
            # Forward HTTPS messages to HTTPS collector
            if category == 'https' and self.https_collector:
                details = payload.get('details', {})
                details['timestamp'] = payload.get('timestamp', datetime.now().timestamp() * 1000)
                
                if action == 'HTTPS_REQUEST':
                    self.https_collector.handle_https_request(details)
                elif action == 'HTTPS_RESPONSE':
                    self.https_collector.handle_https_response(details)
                
                # Also store in API calls for general statistics
                self.statistics['total_https'] += 1
                self.statistics[f"https_{action}"] += 1
                self.statistics['total_calls'] += 1
                
                logger.debug(f"[HTTPS] {action}: {details.get('url', '')}")
                return
            
            self.api_calls.append({
                'timestamp': payload.get('timestamp', datetime.now().timestamp() * 1000),
                'category': category,
                'action': action,
                'details': payload.get('details', {}),
                'stacktrace': payload.get('stacktrace', '')
            })
            
            # Update statistics
            self.statistics[f"{category}_{action}"] += 1
            self.statistics[f"total_{category}"] += 1
            self.statistics['total_calls'] += 1
            
            logger.debug(f"[{category}] {action}: {payload.get('details', {})}")
        
        elif message['type'] == 'error':
            logger.error(f"Frida script error: {message.get('description', '')}")
            logger.error(f"Stack: {message.get('stack', '')}")
    
    def get_api_calls(self, category: str = None) -> List[Dict[str, Any]]:
        """
        Get collected API calls, optionally filtered by category
        
        Args:
            category: Filter by category (network, file, crypto, etc.)
            
        Returns:
            List of API call dictionaries
        """
        if category:
            return [call for call in self.api_calls if call['category'] == category]
        return self.api_calls.copy()
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get API call statistics
        
        Returns:
            Dictionary of statistics
        """
        duration = (datetime.now() - self.start_time).total_seconds()
        
        return {
            'total_calls': self.statistics['total_calls'],
            'duration_seconds': duration,
            'calls_per_second': self.statistics['total_calls'] / duration if duration > 0 else 0,
            'by_category': {
                'network': self.statistics['total_network'],
                'https': self.statistics['total_https'],
                'file': self.statistics['total_file'],
                'crypto': self.statistics['total_crypto'],
                'sms': self.statistics['total_sms'],
                'location': self.statistics['total_location'],
                'contacts': self.statistics['total_contacts'],
                'runtime': self.statistics['total_runtime'],
                'classloader': self.statistics['total_classloader']
            },
            'detailed': dict(self.statistics)
        }
    
    def get_sensitive_behaviors(self) -> Dict[str, List[Dict[str, Any]]]:
        """
        Extract sensitive behaviors from collected data
        
        Returns:
            Dictionary mapping behavior types to examples
        """
        behaviors = {
            'network_communication': [],
            'file_operations': [],
            'cryptography': [],
            'sms_operations': [],
            'location_tracking': [],
            'contacts_access': [],
            'command_execution': [],
            'dynamic_loading': []
        }
        
        for call in self.api_calls:
            category = call['category']
            details = call['details']
            
            if category == 'network':
                behaviors['network_communication'].append({
                    'action': call['action'],
                    'url': details.get('url', ''),
                    'method': details.get('method', ''),
                    'timestamp': call['timestamp']
                })
            
            elif category == 'file':
                behaviors['file_operations'].append({
                    'action': call['action'],
                    'path': details.get('path', ''),
                    'operation': details.get('operation', ''),
                    'timestamp': call['timestamp']
                })
            
            elif category == 'crypto':
                behaviors['cryptography'].append({
                    'action': call['action'],
                    'algorithm': details.get('algorithm') or details.get('transformation', ''),
                    'timestamp': call['timestamp']
                })
            
            elif category == 'sms':
                behaviors['sms_operations'].append({
                    'action': call['action'],
                    'destination': details.get('destination', ''),
                    'text_length': details.get('length', 0),
                    'timestamp': call['timestamp']
                })
            
            elif category == 'location':
                behaviors['location_tracking'].append({
                    'action': call['action'],
                    'provider': details.get('provider', ''),
                    'timestamp': call['timestamp']
                })
            
            elif category == 'contacts':
                behaviors['contacts_access'].append({
                    'action': call['action'],
                    'uri': details.get('uri', ''),
                    'timestamp': call['timestamp']
                })
            
            elif category == 'runtime':
                behaviors['command_execution'].append({
                    'action': call['action'],
                    'command': details.get('command', ''),
                    'timestamp': call['timestamp']
                })
            
            elif category == 'classloader':
                behaviors['dynamic_loading'].append({
                    'action': call['action'],
                    'dexPath': details.get('dexPath', ''),
                    'timestamp': call['timestamp']
                })
        
        # Remove empty categories
        behaviors = {k: v for k, v in behaviors.items() if v}
        
        return behaviors
    
    def save_to_file(self, filename: str = None):
        """
        Save collected data to JSON file
        
        Args:
            filename: Output filename (default: api_calls_<timestamp>.json)
        """
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"api_calls_{timestamp}.json"
        
        output_path = self.output_dir / filename
        
        data = {
            'metadata': {
                'start_time': self.start_time.isoformat(),
                'end_time': datetime.now().isoformat(),
                'total_calls': len(self.api_calls)
            },
            'statistics': self.get_statistics(),
            'sensitive_behaviors': self.get_sensitive_behaviors(),
            'api_calls': self.api_calls
        }
        
        with open(output_path, 'w') as f:
            json.dump(data, f, indent=2)
        
        logger.info(f"✓ API calls saved to: {output_path}")
        return output_path
    
    def clear(self):
        """Clear all collected data"""
        self.api_calls.clear()
        self.statistics.clear()
        self.start_time = datetime.now()
        logger.info("Collected data cleared")
