#!/usr/bin/env python3
"""
API Authorization Security Scanner
Non-intrusive tool for detecting missing/broken API authorization
Author: Security Engineer
"""

import requests
import json
import sys
import time
from urllib.parse import urlparse
from typing import Dict, List, Optional, Tuple
import argparse
from datetime import datetime

class APIAuthScanner:
    def __init__(self, timeout: int = 5, delay: float = 0.5):
        self.timeout = timeout
        self.delay = delay
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'API-Auth-Scanner/1.0 (Security Research)',
            'Accept': 'application/json, text/plain, */*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'close'
        })
        
    def log_result(self, result: Dict):
        """Log results in a structured format"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        print(f"\n[{timestamp}] Authorization Test Result:")
        print(f"Endpoint: {result['endpoint']}")
        print(f"Method: {result['method']}")
        print(f"Test Type: {result['test_type']}")
        print(f"Expected: {result['expected_behavior']}")
        print(f"Actual: {result['actual_behavior']}")
        print(f"Status Code: {result['status_code']}")
        print(f"Severity: {result['severity']}")
        if result.get('error_message'):
            print(f"Error Message: {result['error_message']}")
        print("-" * 60)

    def test_no_auth(self, endpoint: str, method: str = 'GET') -> Optional[Dict]:
        """Test endpoint with no authorization header"""
        try:
            response = self.session.request(
                method=method,
                url=endpoint,
                timeout=self.timeout,
                allow_redirects=False
            )
            
            # Determine if this is a vulnerability
            severity = self._assess_severity(response.status_code, "no_auth")
            
            result = {
                'endpoint': endpoint,
                'method': method,
                'test_type': 'No Authorization Header',
                'expected_behavior': '401 Unauthorized or 403 Forbidden',
                'actual_behavior': self._get_behavior_description(response.status_code),
                'status_code': response.status_code,
                'severity': severity,
                'error_message': self._extract_error_message(response),
                'vulnerable': severity in ['HIGH', 'CRITICAL']
            }
            
            return result
            
        except requests.exceptions.RequestException as e:
            return {
                'endpoint': endpoint,
                'method': method,
                'test_type': 'No Authorization Header',
                'expected_behavior': '401 Unauthorized or 403 Forbidden',
                'actual_behavior': f'Request failed: {str(e)}',
                'status_code': 'ERROR',
                'severity': 'INFO',
                'error_message': str(e),
                'vulnerable': False
            }

    def test_invalid_token(self, endpoint: str, method: str = 'GET') -> Optional[Dict]:
        """Test endpoint with invalid authorization token"""
        headers = {
            'Authorization': 'Bearer invalid_token_12345',
            'Authorization-Type': 'Invalid'
        }
        
        try:
            response = self.session.request(
                method=method,
                url=endpoint,
                headers=headers,
                timeout=self.timeout,
                allow_redirects=False
            )
            
            # Determine if this is a vulnerability
            severity = self._assess_severity(response.status_code, "invalid_token")
            
            result = {
                'endpoint': endpoint,
                'method': method,
                'test_type': 'Invalid Authorization Token',
                'expected_behavior': '401 Unauthorized',
                'actual_behavior': self._get_behavior_description(response.status_code),
                'status_code': response.status_code,
                'severity': severity,
                'error_message': self._extract_error_message(response),
                'vulnerable': severity in ['HIGH', 'CRITICAL']
            }
            
            return result
            
        except requests.exceptions.RequestException as e:
            return {
                'endpoint': endpoint,
                'method': method,
                'test_type': 'Invalid Authorization Token',
                'expected_behavior': '401 Unauthorized',
                'actual_behavior': f'Request failed: {str(e)}',
                'status_code': 'ERROR',
                'severity': 'INFO',
                'error_message': str(e),
                'vulnerable': False
            }

    def _assess_severity(self, status_code: int, test_type: str) -> str:
        """Assess vulnerability severity based on response"""
        if test_type == "no_auth":
            if status_code == 200:
                return 'CRITICAL'
            elif status_code in [201, 202]:
                return 'HIGH'
            elif status_code in [301, 302, 307, 308]:
                return 'MEDIUM'
            elif status_code in [400, 404]:
                return 'LOW'
            elif status_code in [401, 403]:
                return 'SECURE'
            else:
                return 'INFO'
                
        elif test_type == "invalid_token":
            if status_code == 200:
                return 'CRITICAL'
            elif status_code in [201, 202]:
                return 'HIGH'
            elif status_code in [301, 302, 307, 308]:
                return 'MEDIUM'
            elif status_code in [400, 404]:
                return 'LOW'
            elif status_code == 401:
                return 'SECURE'
            else:
                return 'INFO'

    def _get_behavior_description(self, status_code: int) -> str:
        """Get human-readable description of status code"""
        descriptions = {
            200: 'OK - Access granted',
            201: 'Created - Resource created',
            202: 'Accepted - Request accepted',
            301: 'Moved Permanently',
            302: 'Found - Redirect',
            307: 'Temporary Redirect',
            308: 'Permanent Redirect',
            400: 'Bad Request',
            401: 'Unauthorized',
            403: 'Forbidden',
            404: 'Not Found',
            500: 'Internal Server Error',
            502: 'Bad Gateway',
            503: 'Service Unavailable'
        }
        return descriptions.get(status_code, f'Unknown status code: {status_code}')

    def _extract_error_message(self, response: requests.Response) -> str:
        """Extract error message from response (non-intrusive)"""
        try:
            if response.headers.get('content-type', '').startswith('application/json'):
                data = response.json()
                # Only extract top-level error fields, no deep traversal
                if isinstance(data, dict):
                    for key in ['error', 'message', 'msg', 'detail']:
                        if key in data and isinstance(data[key], str):
                            return data[key][:100]  # Limit to 100 chars
            elif response.headers.get('content-type', '').startswith('text/'):
                text = response.text[:100]  # First 100 chars only
                return text.strip()
        except:
            pass
        return ''

    def scan_endpoint(self, endpoint: str, method: str = 'GET') -> List[Dict]:
        """Scan a single endpoint for authorization issues"""
        results = []
        
        print(f"\n[*] Scanning endpoint: {endpoint} ({method})")
        
        # Test 1: No authorization header
        print("[*] Testing with no authorization header...")
        result1 = self.test_no_auth(endpoint, method)
        if result1:
            results.append(result1)
            self.log_result(result1)
            
            # Stop if critical vulnerability found
            if result1['severity'] == 'CRITICAL':
                print("[!] CRITICAL vulnerability found! Stopping further tests on this endpoint.")
                return results
        
        time.sleep(self.delay)
        
        # Test 2: Invalid authorization token
        print("[*] Testing with invalid authorization token...")
        result2 = self.test_invalid_token(endpoint, method)
        if result2:
            results.append(result2)
            self.log_result(result2)
            
            # Stop if critical vulnerability found
            if result2['severity'] == 'CRITICAL':
                print("[!] CRITICAL vulnerability found! Stopping further tests on this endpoint.")
        
        return results

    def scan_endpoints(self, endpoints: List[str], methods: List[str] = None) -> Dict:
        """Scan multiple endpoints"""
        if methods is None:
            methods = ['GET']
            
        all_results = []
        vulnerable_endpoints = []
        
        print(f"[*] Starting API authorization scan on {len(endpoints)} endpoints...")
        
        for endpoint in endpoints:
            for method in methods:
                try:
                    results = self.scan_endpoint(endpoint, method)
                    all_results.extend(results)
                    
                    # Check if any results indicate vulnerabilities
                    for result in results:
                        if result.get('vulnerable', False):
                            vulnerable_endpoints.append({
                                'endpoint': endpoint,
                                'method': method,
                                'severity': result['severity'],
                                'issue': result['test_type']
                            })
                            
                except KeyboardInterrupt:
                    print("\n[!] Scan interrupted by user")
                    break
                except Exception as e:
                    print(f"[!] Error scanning {endpoint}: {str(e)}")
                    continue
        
        # Generate summary
        summary = self._generate_summary(all_results, vulnerable_endpoints)
        return summary

    def _generate_summary(self, results: List[Dict], vulnerable_endpoints: List[Dict]) -> Dict:
        """Generate scan summary"""
        total_tests = len(results)
        vulnerable_count = len([r for r in results if r.get('vulnerable', False)])
        critical_count = len([r for r in results if r['severity'] == 'CRITICAL'])
        high_count = len([r for r in results if r['severity'] == 'HIGH'])
        
        summary = {
            'scan_summary': {
                'total_tests': total_tests,
                'vulnerable_tests': vulnerable_count,
                'critical_issues': critical_count,
                'high_issues': high_count,
                'secure_tests': total_tests - vulnerable_count
            },
            'vulnerable_endpoints': vulnerable_endpoints,
            'all_results': results
        }
        
        print("\n" + "="*60)
        print("SCAN SUMMARY")
        print("="*60)
        print(f"Total Tests: {total_tests}")
        print(f"Vulnerable Tests: {vulnerable_count}")
        print(f"Critical Issues: {critical_count}")
        print(f"High Issues: {high_count}")
        print(f"Secure Tests: {total_tests - vulnerable_count}")
        
        if vulnerable_endpoints:
            print("\nVULNERABLE ENDPOINTS:")
            for vuln in vulnerable_endpoints:
                print(f"  - {vuln['method']} {vuln['endpoint']} ({vuln['severity']}) - {vuln['issue']}")
        
        return summary

def validate_url(url: str) -> bool:
    """Validate URL format"""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False

def main():
    parser = argparse.ArgumentParser(
        description='Non-intrusive API Authorization Security Scanner',
        epilog='Example: python api_auth_scanner.py -u https://api.example.com/users -m GET POST'
    )
    
    parser.add_argument('-u', '--urls', nargs='+', required=True,
                        help='API endpoints to test')
    parser.add_argument('-m', '--methods', nargs='+', default=['GET'],
                        help='HTTP methods to test (default: GET)')
    parser.add_argument('-t', '--timeout', type=int, default=5,
                        help='Request timeout in seconds (default: 5)')
    parser.add_argument('-d', '--delay', type=float, default=0.5,
                        help='Delay between requests in seconds (default: 0.5)')
    parser.add_argument('-o', '--output', type=str,
                        help='Output file for results (JSON format)')
    
    args = parser.parse_args()
    
    # Validate URLs
    for url in args.urls:
        if not validate_url(url):
            print(f"[!] Invalid URL: {url}")
            sys.exit(1)
    
    # Initialize scanner
    scanner = APIAuthScanner(timeout=args.timeout, delay=args.delay)
    
    # Perform scan
    try:
        summary = scanner.scan_endpoints(args.urls, args.methods)
        
        # Save results if output file specified
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(summary, f, indent=2)
            print(f"\n[*] Results saved to: {args.output}")
            
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Scan failed: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()