"""
HTTPS Collector - Collects and stores HTTPS interception data from Frida
Phase 2.5: Lightweight HTTPS decryption without mitmproxy
"""
import json
import logging
from pathlib import Path
from typing import Dict, Any, List
from datetime import datetime
from collections import defaultdict

logger = logging.getLogger(__name__)


class HTTPSCollector:
    """
    Collects HTTPS request/response data intercepted by Frida hooks
    """
    
    def __init__(self, output_dir: str):
        """
        Initialize HTTPS collector
        
        Args:
            output_dir: Directory to store collected data
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # In-memory storage
        self.https_requests: List[Dict[str, Any]] = []
        self.https_responses: List[Dict[str, Any]] = []
        self.statistics = defaultdict(int)
        self.start_time = datetime.now()
        
        logger.info(f"HTTPSCollector initialized, output dir: {output_dir}")
    
    def handle_https_request(self, data: Dict[str, Any]):
        """
        Handle HTTPS request data from Frida (HTTP or binary protocols like gRPC/protobuf)
        
        Args:
            data: Request data dictionary
        """
        protocol = data.get('protocol', 'unknown')
        
        request = {
            'timestamp': data.get('timestamp', datetime.now().timestamp() * 1000),
            'protocol': protocol,
            'url': data.get('url', ''),
            'method': data.get('method', 'GET'),
            'headers': data.get('headers', ''),
            'body': data.get('body', '') if protocol == 'HTTP' else None,
            'binary_size': data.get('size', 0) if protocol != 'HTTP' else None,
            'hex_preview': data.get('hex_preview', '') if protocol != 'HTTP' else None,
            'raw_bytes': data.get('raw_bytes', []) if protocol != 'HTTP' else None,
            'body_length': data.get('body_length', 0)
        }
        
        self.https_requests.append(request)
        self.statistics['total_requests'] += 1
        self.statistics[f"method_{request['method']}"] += 1
        
        # Extract domain for statistics
        try:
            from urllib.parse import urlparse
            domain = urlparse(request['url']).netloc
            self.statistics[f"domain_{domain}"] += 1
        except:
            pass
        
        logger.debug(f"[HTTPS Request] {request['method']} {request['url']} ({request['body_length']} bytes)")
    
    def handle_https_response(self, data: Dict[str, Any]):
        """
        Handle HTTPS response data from Frida
        
        Args:
            data: Response data dictionary
        """
        response = {
            'timestamp': data.get('timestamp', datetime.now().timestamp() * 1000),
            'protocol': data.get('protocol', 'unknown'),
            'url': data.get('url', ''),
            'status_code': data.get('status_code', 0),
            'headers': data.get('headers', ''),
            'body': data.get('body', ''),
            'body_length': data.get('body_length', 0),
            'truncated': data.get('truncated', False)
        }
        
        self.https_responses.append(response)
        self.statistics['total_responses'] += 1
        self.statistics[f"status_{response['status_code']}"] += 1
        
        logger.debug(f"[HTTPS Response] {response['status_code']} {response['url']} ({response['body_length']} bytes)")
    
    def get_requests(self, url_filter: str = None) -> List[Dict[str, Any]]:
        """
        Get collected HTTPS requests, optionally filtered by URL
        
        Args:
            url_filter: Filter by URL substring (optional)
            
        Returns:
            List of request dictionaries
        """
        if url_filter:
            return [req for req in self.https_requests if url_filter in req['url']]
        return self.https_requests.copy()
    
    def get_responses(self, url_filter: str = None) -> List[Dict[str, Any]]:
        """
        Get collected HTTPS responses, optionally filtered by URL
        
        Args:
            url_filter: Filter by URL substring (optional)
            
        Returns:
            List of response dictionaries
        """
        if url_filter:
            return [resp for resp in self.https_responses if url_filter in resp['url']]
        return self.https_responses.copy()
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get HTTPS interception statistics
        
        Returns:
            Dictionary of statistics
        """
        duration = (datetime.now() - self.start_time).total_seconds()
        
        # Calculate unique domains
        unique_domains = set()
        for req in self.https_requests:
            try:
                from urllib.parse import urlparse
                domain = urlparse(req['url']).netloc
                unique_domains.add(domain)
            except:
                pass
        
        return {
            'total_requests': self.statistics['total_requests'],
            'total_responses': self.statistics['total_responses'],
            'unique_domains': len(unique_domains),
            'duration_seconds': duration,
            'requests_per_second': self.statistics['total_requests'] / duration if duration > 0 else 0,
            'by_method': {
                'GET': self.statistics.get('method_GET', 0),
                'POST': self.statistics.get('method_POST', 0),
                'PUT': self.statistics.get('method_PUT', 0),
                'DELETE': self.statistics.get('method_DELETE', 0),
                'PATCH': self.statistics.get('method_PATCH', 0),
            },
            'detailed': dict(self.statistics)
        }
    
    def get_sensitive_data(self) -> Dict[str, List[Dict[str, Any]]]:
        """
        Extract potentially sensitive data from HTTPS traffic
        
        Returns:
            Dictionary mapping data types to examples
        """
        sensitive = {
            'authentication': [],
            'api_keys': [],
            'personal_data': [],
            'suspicious_urls': [],
            'data_exfiltration': []
        }
        
        # Patterns for sensitive data
        auth_keywords = ['password', 'passwd', 'pwd', 'token', 'auth', 'session', 'cookie', 'bearer']
        api_key_patterns = ['api_key', 'apikey', 'api-key', 'key=', 'secret']
        personal_keywords = ['email', 'phone', 'ssn', 'credit', 'card', 'address']
        suspicious_domains = ['pastebin', 'hastebin', 'discord', 'telegram', 'raw.githubusercontent']
        
        # Scan requests
        for req in self.https_requests:
            url_lower = req['url'].lower()
            body_lower = req['body'].lower() if req['body'] else ''
            headers_lower = req['headers'].lower() if req['headers'] else ''
            
            # Check for authentication
            if any(keyword in url_lower or keyword in body_lower or keyword in headers_lower for keyword in auth_keywords):
                sensitive['authentication'].append({
                    'type': 'request',
                    'url': req['url'],
                    'method': req['method'],
                    'body_snippet': req['body'][:200] if req['body'] else '',
                    'timestamp': req['timestamp']
                })
            
            # Check for API keys
            if any(pattern in url_lower or pattern in body_lower for pattern in api_key_patterns):
                sensitive['api_keys'].append({
                    'type': 'request',
                    'url': req['url'],
                    'body_snippet': req['body'][:200] if req['body'] else '',
                    'timestamp': req['timestamp']
                })
            
            # Check for personal data
            if any(keyword in body_lower for keyword in personal_keywords):
                sensitive['personal_data'].append({
                    'type': 'request',
                    'url': req['url'],
                    'data_type': [kw for kw in personal_keywords if kw in body_lower],
                    'timestamp': req['timestamp']
                })
            
            # Check for suspicious URLs (data exfiltration)
            if any(domain in url_lower for domain in suspicious_domains):
                sensitive['suspicious_urls'].append({
                    'type': 'request',
                    'url': req['url'],
                    'reason': 'Known data exfiltration service',
                    'body_length': req['body_length'],
                    'timestamp': req['timestamp']
                })
        
        # Scan responses for sensitive data
        for resp in self.https_responses:
            body_lower = resp['body'].lower() if resp['body'] else ''
            
            # Check for authentication tokens in responses
            if any(keyword in body_lower for keyword in auth_keywords):
                sensitive['authentication'].append({
                    'type': 'response',
                    'url': resp['url'],
                    'status_code': resp['status_code'],
                    'body_snippet': resp['body'][:200] if resp['body'] else '',
                    'timestamp': resp['timestamp']
                })
        
        # Detect potential data exfiltration (large POST requests)
        large_posts = [req for req in self.https_requests 
                      if req['method'] == 'POST' and req['body_length'] > 10000]
        
        for req in large_posts:
            sensitive['data_exfiltration'].append({
                'url': req['url'],
                'method': req['method'],
                'size_bytes': req['body_length'],
                'timestamp': req['timestamp'],
                'reason': 'Large POST request (potential data upload)'
            })
        
        return sensitive
    
    def save_to_file(self) -> Path:
        """
        Save collected HTTPS data to JSON file
        
        Returns:
            Path to saved file
        """
        output_file = self.output_dir / "https_traffic.json"
        
        data = {
            'metadata': {
                'start_time': self.start_time.isoformat(),
                'end_time': datetime.now().isoformat(),
                'duration_seconds': (datetime.now() - self.start_time).total_seconds(),
                'total_requests': len(self.https_requests),
                'total_responses': len(self.https_responses)
            },
            'statistics': self.get_statistics(),
            'sensitive_data': self.get_sensitive_data(),
            'requests': self.https_requests,
            'responses': self.https_responses
        }
        
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2)
        
        logger.info(f"✓ HTTPS traffic saved: {output_file}")
        logger.info(f"  - Requests: {len(self.https_requests)}")
        logger.info(f"  - Responses: {len(self.https_responses)}")
        logger.info(f"  - Sensitive findings: {sum(len(v) for v in self.get_sensitive_data().values())}")
        
        return output_file
    
    def generate_summary_report(self) -> Dict[str, Any]:
        """
        Generate a summary report of HTTPS traffic
        
        Returns:
            Dictionary with summary data
        """
        stats = self.get_statistics()
        sensitive = self.get_sensitive_data()
        
        # Top domains
        domain_counts = {}
        for req in self.https_requests:
            try:
                from urllib.parse import urlparse
                domain = urlparse(req['url']).netloc
                domain_counts[domain] = domain_counts.get(domain, 0) + 1
            except:
                pass
        
        top_domains = sorted(domain_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        
        # Status code distribution
        status_codes = {}
        for resp in self.https_responses:
            code = resp['status_code']
            status_codes[code] = status_codes.get(code, 0) + 1
        
        return {
            'summary': {
                'total_requests': stats['total_requests'],
                'total_responses': stats['total_responses'],
                'unique_domains': stats['unique_domains'],
                'duration': f"{stats['duration_seconds']:.1f}s",
                'requests_per_second': f"{stats['requests_per_second']:.2f}"
            },
            'methods': stats['by_method'],
            'top_domains': [{'domain': d, 'count': c} for d, c in top_domains],
            'status_codes': status_codes,
            'sensitive_findings': {
                'authentication': len(sensitive['authentication']),
                'api_keys': len(sensitive['api_keys']),
                'personal_data': len(sensitive['personal_data']),
                'suspicious_urls': len(sensitive['suspicious_urls']),
                'data_exfiltration': len(sensitive['data_exfiltration'])
            }
        }
