#!/usr/bin/env python3
"""
Cloud Service Exposure Detector
Read-only tool for detecting publicly accessible cloud services
Author: Security Research Team
"""

import requests
import sys
import json
import urllib3
from urllib.parse import urlparse
from typing import Dict, List, Optional
import concurrent.futures
import time

# Disable SSL warnings for research purposes
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class CloudExposureDetector:
    def __init__(self, timeout: int = 5, max_workers: int = 10):
        self.timeout = timeout
        self.max_workers = max_workers
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'CloudSec-Research/1.0 (Security Research)',
            'Accept': 'text/html,application/xhtml+xml',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        })
        
        # Service detection patterns
        self.service_patterns = {
            'grafana': {
                'title_patterns': ['grafana', 'grafana labs'],
                'header_patterns': ['x-grafana', 'grafana'],
                'version_indicators': ['grafana-', 'grafana_'],
                'landing_paths': ['/login', '/api/health', '/']
            },
            'prometheus': {
                'title_patterns': ['prometheus', 'prometheus time series'],
                'header_patterns': ['x-prometheus', 'prometheus'],
                'version_indicators': ['prometheus/', 'prometheus-'],
                'landing_paths': ['/graph', '/api/v1/', '/']
            },
            'kibana': {
                'title_patterns': ['kibana', 'elastic'],
                'header_patterns': ['kbn-', 'kibana'],
                'version_indicators': ['kibana/', 'kbn-'],
                'landing_paths': ['/login', '/api/status', '/app/kibana', '/']
            }
        }
        
        # Risk classifications
        self.risk_levels = {
            'CRITICAL': 'Publicly accessible with no authentication',
            'HIGH': 'Accessible but may require authentication',
            'MEDIUM': 'Service detected but access restricted',
            'LOW': 'Service likely not exposed or protected'
        }

    def detect_service_type(self, url: str, response: requests.Response) -> Dict[str, any]:
        """Detect service type based on response characteristics"""
        service_info = {
            'service': 'unknown',
            'version': None,
            'authentication_required': 'unknown',
            'risk_level': 'LOW'
        }
        
        content = response.text.lower() if response.text else ''
        title = self._extract_title(content)
        headers = {k.lower(): v.lower() for k, v in response.headers.items()}
        
        # Check each service pattern
        for service, patterns in self.service_patterns.items():
            score = 0
            
            # Check title patterns
            if any(pattern in title for pattern in patterns['title_patterns']):
                score += 3
                
            # Check header patterns
            for header_name, header_value in headers.items():
                if any(pattern in header_name for pattern in patterns['header_patterns']):
                    score += 2
                if any(pattern in header_value for pattern in patterns['version_indicators']):
                    score += 2
                    
            # Check content patterns
            if any(pattern in content for pattern in patterns['title_patterns']):
                score += 1
                
            # Check for version indicators in content
            for pattern in patterns['version_indicators']:
                if pattern in content:
                    service_info['version'] = self._extract_version(content, pattern)
                    score += 1
                    
            if score >= 3:  # Threshold for service detection
                service_info['service'] = service
                break
                
        return service_info

    def _extract_title(self, content: str) -> str:
        """Extract page title from HTML content"""
        import re
        title_match = re.search(r'<title[^>]*>([^<]+)</title>', content, re.IGNORECASE)
        return title_match.group(1).strip().lower() if title_match else ''

    def _extract_version(self, content: str, pattern: str) -> Optional[str]:
        """Extract version information from content"""
        import re
        version_pattern = re.escape(pattern) + r'([0-9]+\.[0-9]+(?:\.[0-9]+)?)'
        version_match = re.search(version_pattern, content, re.IGNORECASE)
        return version_match.group(1) if version_match else None

    def check_authentication(self, url: str, response: requests.Response, service: str) -> str:
        """Determine if authentication is required"""
        status_code = response.status_code
        
        # Authentication indicators
        auth_indicators = {
            'grafana': {
                'required': [401, 403],
                'login_paths': ['/login', '/api/login'],
                'auth_headers': ['www-authenticate', 'location']
            },
            'prometheus': {
                'required': [401, 403],
                'login_paths': ['/login'],
                'auth_headers': ['www-authenticate']
            },
            'kibana': {
                'required': [401, 403, 302],  # Kibana often redirects to login
                'login_paths': ['/login', '/app/login'],
                'auth_headers': ['www-authenticate', 'location', 'kbn-license-sig']
            }
        }
        
        service_patterns = auth_indicators.get(service, auth_indicators['grafana'])
        
        # Check status codes
        if status_code in service_patterns['required']:
            return 'yes'
            
        # Check for login redirects
        if status_code == 302:
            location = response.headers.get('Location', '').lower()
            if any(path in location for path in service_patterns['login_paths']):
                return 'yes'
                
        # Check for authentication headers
        for header in service_patterns['auth_headers']:
            if header in response.headers:
                return 'yes'
                
        # Check response content for login forms
        content = response.text.lower()
        login_indicators = ['login', 'sign in', 'authentication', 'password']
        if any(indicator in content for indicator in login_indicators):
            return 'likely'
            
        return 'no'

    def assess_risk(self, service: str, auth_required: str, status_code: int) -> str:
        """Assess exposure risk level"""
        if auth_required == 'no' and status_code == 200:
            return 'CRITICAL'
        elif auth_required in ['likely', 'unknown'] and status_code == 200:
            return 'HIGH'
        elif auth_required == 'yes' and status_code in [401, 403]:
            return 'MEDIUM'
        else:
            return 'LOW'

    def check_endpoint(self, url: str) -> Dict[str, any]:
        """Check a single endpoint for service exposure"""
        result = {
            'url': url,
            'service': 'unknown',
            'public_accessible': False,
            'authentication_required': 'unknown',
            'risk_level': 'LOW',
            'status_code': 0,
            'response_time': 0,
            'error': None
        }
        
        try:
            start_time = time.time()
            
            # Perform HEAD request first (less intrusive)
            head_response = self.session.head(
                url, 
                timeout=self.timeout, 
                verify=False,
                allow_redirects=True
            )
            
            # If HEAD is blocked, try GET but limit response size
            if head_response.status_code == 405:  # Method not allowed
                response = self.session.get(
                    url,
                    timeout=self.timeout,
                    verify=False,
                    allow_redirects=True,
                    stream=True
                )
                # Limit response size to 1KB for safety
                response._content = response.raw.read(1024)
            else:
                response = head_response
                
            response_time = time.time() - start_time
            
            result.update({
                'status_code': response.status_code,
                'response_time': round(response_time, 2),
                'public_accessible': response.status_code < 500
            })
            
            # Only analyze if service is accessible
            if result['public_accessible']:
                service_info = self.detect_service_type(url, response)
                auth_required = self.check_authentication(url, response, service_info['service'])
                risk_level = self.assess_risk(service_info['service'], auth_required, response.status_code)
                
                result.update({
                    'service': service_info['service'],
                    'authentication_required': auth_required,
                    'risk_level': risk_level
                })
                
                # Add version if detected
                if service_info.get('version'):
                    result['version'] = service_info['version']
                    
        except requests.exceptions.RequestException as e:
            result['error'] = str(e)
            result['risk_level'] = 'LOW'
            
        return result

    def scan_targets(self, targets: List[str]) -> List[Dict[str, any]]:
        """Scan multiple targets concurrently"""
        results = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_url = {executor.submit(self.check_endpoint, url): url for url in targets}
            
            for future in concurrent.futures.as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    results.append({
                        'url': url,
                        'service': 'error',
                        'error': str(e),
                        'risk_level': 'LOW'
                    })
                    
        return results

    def generate_report(self, results: List[Dict[str, any]], output_format: str = 'json') -> str:
        """Generate scan report"""
        summary = {
            'total_scanned': len(results),
            'services_detected': sum(1 for r in results if r['service'] != 'unknown' and r['service'] != 'error'),
            'critical_exposures': sum(1 for r in results if r['risk_level'] == 'CRITICAL'),
            'high_risk': sum(1 for r in results if r['risk_level'] == 'HIGH'),
            'medium_risk': sum(1 for r in results if r['risk_level'] == 'MEDIUM'),
            'low_risk': sum(1 for r in results if r['risk_level'] == 'LOW')
        }
        
        report = {
            'scan_summary': summary,
            'risk_explanations': self.risk_levels,
            'results': results,
            'scan_timestamp': time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())
        }
        
        if output_format == 'json':
            return json.dumps(report, indent=2, default=str)
        else:
            # Simple text format
            output = []
            output.append("=== Cloud Service Exposure Detection Report ===")
            output.append(f"Scanned: {summary['total_scanned']} targets")
            output.append(f"Services detected: {summary['services_detected']}")
            output.append(f"Critical exposures: {summary['critical_exposures']}")
            output.append(f"High risk: {summary['high_risk']}")
            output.append("")
            
            for result in results:
                if result['service'] != 'unknown' and result['service'] != 'error':
                    output.append(f"Service: {result['service'].upper()}")
                    output.append(f"URL: {result['url']}")
                    output.append(f"Status: {result['status_code']}")
                    output.append(f"Auth Required: {result['authentication_required']}")
                    output.append(f"Risk Level: {result['risk_level']}")
                    if 'version' in result:
                        output.append(f"Version: {result['version']}")
                    output.append("-" * 40)
                    
            return '\n'.join(output)

def main():
    """Main function with CLI interface"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Cloud Service Exposure Detector - Read Only')
    parser.add_argument('targets', nargs='+', help='Target URLs to scan')
    parser.add_argument('-t', '--timeout', type=int, default=5, help='Request timeout (seconds)')
    parser.add_argument('-w', '--workers', type=int, default=10, help='Concurrent workers')
    parser.add_argument('-o', '--output', choices=['json', 'text'], default='text', help='Output format')
    parser.add_argument('-f', '--file', help='Read targets from file (one per line)')
    
    args = parser.parse_args()
    
    # Collect targets
    targets = args.targets.copy()
    if args.file:
        try:
            with open(args.file, 'r') as f:
                targets.extend([line.strip() for line in f if line.strip()])
        except FileNotFoundError:
            print(f"Error: File {args.file} not found")
            sys.exit(1)
    
    # Validate URLs
    valid_targets = []
    for target in targets:
        if not target.startswith(('http://', 'https://')):
            target = f'https://{target}'
        try:
            result = urlparse(target)
            if result.scheme and result.netloc:
                valid_targets.append(target)
        except:
            print(f"Warning: Invalid URL format: {target}")
            continue
    
    if not valid_targets:
        print("Error: No valid targets provided")
        sys.exit(1)
    
    # Initialize detector
    detector = CloudExposureDetector(timeout=args.timeout, max_workers=args.workers)
    
    print(f"Starting cloud service exposure scan for {len(valid_targets)} targets...")
    print("Note: This tool performs read-only detection only")
    print("=" * 60)
    
    # Perform scan
    results = detector.scan_targets(valid_targets)
    
    # Generate and output report
    report = detector.generate_report(results, args.output)
    print(report)
    
    # Exit with appropriate code
    critical_count = sum(1 for r in results if r['risk_level'] == 'CRITICAL')
    if critical_count > 0:
        sys.exit(2)  # Critical exposures found
    else:
        sys.exit(0)

if __name__ == '__main__':
    main()