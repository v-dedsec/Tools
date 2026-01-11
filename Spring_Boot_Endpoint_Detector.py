#!/usr/bin/env python3
"""
Spring Boot Actuator Security Scanner
A defensive, read-only tool for detecting potentially exposed Spring Boot Actuator endpoints.
Author: Security Researcher
Version: 1.0.0

DISCLAIMER: This tool is for authorized security testing only.
Use only on systems you own or have explicit permission to test.
"""

import requests
import argparse
import sys
import re
import time
from urllib.parse import urljoin, urlparse
from typing import Dict, List, Set, Optional
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Constants for safety
MAX_RESPONSE_SIZE = 1024  # 1KB maximum response size
REQUEST_TIMEOUT = 5      # 5 second timeout
RATE_LIMIT_DELAY = 0.5   # 0.5 second delay between requests
USER_AGENT = "SecurityScanner/1.0 (Compatible; Research Purpose)"

class SecurityConstraints:
    """Security constraints and safety mechanisms"""
    
    SENSITIVE_ENDPOINTS = {
        '/actuator/heapdump',
        '/actuator/env',
        '/actuator/configprops',
        '/actuator/mappings',
        '/actuator/threaddump',
        '/actuator/logfile',
        '/actuator/dump',
        '/actuator/trace',
        '/actuator/httptrace',
        '/actuator/auditevents'
    }
    
    SAFE_ENDPOINTS = {
        '/actuator',
        '/actuator/health',
        '/health',
        '/actuator/info',
        '/info'
    }
    
    SPRING_INDICATORS = [
        'spring',
        'boot',
        'actuator',
        'whitelabel error page',
        'application/json',
        'hal+json'
    ]

class SpringBootActuatorScanner:
    """Defensive Spring Boot Actuator endpoint scanner"""
    
    def __init__(self, timeout: int = REQUEST_TIMEOUT, max_size: int = MAX_RESPONSE_SIZE):
        self.timeout = timeout
        self.max_size = max_size
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': USER_AGENT,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        })
    
    def _safe_request(self, url: str, method: str = 'GET', headers_only: bool = False) -> Optional[requests.Response]:
        """
        Perform a safe HTTP request with strict safety constraints
        
        Args:
            url: Target URL
            method: HTTP method
            headers_only: Only fetch headers (HEAD request)
            
        Returns:
            Response object or None if safety constraints violated
        """
        try:
            if headers_only:
                response = self.session.head(
                    url, 
                    timeout=self.timeout,
                    allow_redirects=False,
                    verify=False  # For testing purposes only
                )
            else:
                response = self.session.get(
                    url,
                    timeout=self.timeout,
                    allow_redirects=False,
                    stream=True,  # Stream to check content length
                    verify=False
                )
            
            # Check response size before downloading
            content_length = response.headers.get('Content-Length')
            if content_length and int(content_length) > self.max_size:
                logger.warning(f"Response too large ({content_length} bytes), aborting: {url}")
                return None
            
            # For GET requests, read only up to max_size
            if not headers_only and response.status_code == 200:
                content = response.raw.read(self.max_size + 1, decode_content=True)
                if len(content) > self.max_size:
                    logger.warning(f"Response body exceeds maximum size, aborting: {url}")
                    return None
                # Create a new response object with limited content
                response._content = content
            
            return response
            
        except requests.exceptions.RequestException as e:
            logger.debug(f"Request failed for {url}: {str(e)}")
            return None
    
    def detect_spring_boot_technology(self, base_url: str) -> bool:
        """
        Perform passive technology fingerprinting to identify Spring Boot applications
        
        Args:
            base_url: Base URL of the target
            
        Returns:
            True if Spring Boot detected
        """
        try:
            # Check common Spring Boot indicators
            response = self._safe_request(base_url)
            if not response:
                return False
            
            indicators_found = []
            
            # Check response headers
            server_header = response.headers.get('Server', '').lower()
            if 'spring' in server_header or 'boot' in server_header:
                indicators_found.append('server_header')
            
            # Check response content
            if response.text:
                content_lower = response.text.lower()
                for indicator in SecurityConstraints.SPRING_INDICATORS:
                    if indicator in content_lower:
                        indicators_found.append(f'content_{indicator}')
                        break
            
            # Check for Spring-specific cookies
            if 'Set-Cookie' in response.headers:
                cookies = response.headers['Set-Cookie'].lower()
                if 'session' in cookies and 'path=/' in cookies:
                    indicators_found.append('session_cookie')
            
            # Check X-Application-Context header (Spring specific)
            if 'X-Application-Context' in response.headers:
                indicators_found.append('application_context_header')
            
            logger.info(f"Spring Boot indicators found: {len(indicators_found)} - {indicators_found}")
            return len(indicators_found) >= 2
            
        except Exception as e:
            logger.error(f"Technology detection error: {str(e)}")
            return False
    
    def check_endpoint_safely(self, base_url: str, endpoint: str, headers_only: bool = False) -> Dict:
        """
        Safely check if an endpoint exists and is accessible
        
        Args:
            base_url: Base URL
            endpoint: Endpoint path
            headers_only: Only check headers
            
        Returns:
            Dictionary with endpoint status information
        """
        url = urljoin(base_url.rstrip('/'), endpoint)
        
        try:
            response = self._safe_request(url, headers_only=headers_only)
            
            if not response:
                return {
                    'endpoint': endpoint,
                    'accessible': False,
                    'status_code': None,
                    'error': 'Safety constraint violated or request failed'
                }
            
            result = {
                'endpoint': endpoint,
                'accessible': response.status_code in [200, 401, 403],
                'status_code': response.status_code,
                'headers': dict(response.headers) if response else {},
                'error': None
            }
            
            # Check for authentication requirements
            if response.status_code in [401, 403]:
                result['protected'] = True
            
            return result
            
        except Exception as e:
            return {
                'endpoint': endpoint,
                'accessible': False,
                'status_code': None,
                'error': str(e)
            }
    
    def parse_actuator_index(self, response_text: str) -> Set[str]:
        """
        Parse actuator index page to discover available endpoints
        
        Args:
            response_text: Response text from /actuator endpoint
            
        Returns:
            Set of discovered endpoint paths
        """
        discovered_endpoints = set()
        
        try:
            # Look for links in HTML content
            link_pattern = r'href=["\']([^"\']+)["\']'
            links = re.findall(link_pattern, response_text, re.IGNORECASE)
            
            for link in links:
                if link.startswith('/actuator/'):
                    discovered_endpoints.add(link)
            
            # Look for JSON-style endpoint listings
            if '{' in response_text and '}' in response_text:
                # Simple pattern matching for endpoint names
                endpoint_pattern = r'["\']([^"\']+)["\']\s*:\s*["\'][^"\']*["\']'
                matches = re.findall(endpoint_pattern, response_text)
                for match in matches:
                    if match not in ['_links', 'self']:
                        endpoint = f'/actuator/{match}'
                        discovered_endpoints.add(endpoint)
            
        except Exception as e:
            logger.error(f"Error parsing actuator index: {str(e)}")
        
        return discovered_endpoints
    
    def assess_risk_level(self, results: Dict) -> str:
        """
        Assess the risk level based on scan results
        
        Args:
            results: Scan results dictionary
            
        Returns:
            Risk level classification
        """
        exposed_sensitive = results.get('exposed_sensitive_endpoints', [])
        exposed_safe = results.get('exposed_safe_endpoints', [])
        technology_detected = results.get('spring_boot_detected', False)
        
        if not technology_detected:
            return "Inconclusive"
        
        if exposed_sensitive:
            return "High Risk - Potentially Exposed"
        
        if exposed_safe:
            return "Medium Risk - Monitor"
        
        if results.get('actuator_index_accessible'):
            return "Low Risk - Configuration Review Recommended"
        
        return "Secure"
    
    def scan_target(self, target_url: str) -> Dict:
        """
        Perform comprehensive scan of a single target
        
        Args:
            target_url: Target URL to scan
            
        Returns:
            Scan results dictionary
        """
        logger.info(f"Starting scan of: {target_url}")
        
        results = {
            'target': target_url,
            'spring_boot_detected': False,
            'exposed_safe_endpoints': [],
            'exposed_sensitive_endpoints': [],
            'actuator_index_accessible': False,
            'discovered_endpoints': [],
            'risk_level': 'Inconclusive',
            'scan_timestamp': time.time()
        }
        
        # Step 1: Technology detection
        logger.info("Detecting Spring Boot technology...")
        results['spring_boot_detected'] = self.detect_spring_boot_technology(target_url)
        
        if not results['spring_boot_detected']:
            logger.info("Spring Boot not detected, scan inconclusive")
            return results
        
        # Step 2: Check safe endpoints
        logger.info("Checking safe endpoints...")
        for endpoint in SecurityConstraints.SAFE_ENDPOINTS:
            time.sleep(RATE_LIMIT_DELAY)  # Rate limiting
            
            endpoint_result = self.check_endpoint_safely(target_url, endpoint)
            if endpoint_result['accessible'] and endpoint_result['status_code'] == 200:
                results['exposed_safe_endpoints'].append(endpoint)
                
                # Special handling for actuator index
                if endpoint == '/actuator':
                    results['actuator_index_accessible'] = True
                    # Parse the index to discover other endpoints
                    response = self._safe_request(urljoin(target_url, endpoint))
                    if response and response.text:
                        discovered = self.parse_actuator_index(response.text)
                        results['discovered_endpoints'] = list(discovered)
        
        # Step 3: Safely check for sensitive endpoints (headers only)
        logger.info("Checking sensitive endpoints (headers only)...")
        for endpoint in SecurityConstraints.SENSITIVE_ENDPOINTS:
            time.sleep(RATE_LIMIT_DELAY)
            
            # Always use headers-only for sensitive endpoints
            endpoint_result = self.check_endpoint_safely(target_url, endpoint, headers_only=True)
            
            if endpoint_result['accessible'] and endpoint_result['status_code'] == 200:
                results['exposed_sensitive_endpoints'].append(endpoint)
                logger.warning(f"SENSITIVE ENDPOINT EXPOSED: {endpoint}")
        
        # Step 4: Risk assessment
        results['risk_level'] = self.assess_risk_level(results)
        
        return results
    
    def print_summary(self, results: Dict):
        """
        Print a concise summary of scan results
        
        Args:
            results: Scan results dictionary
        """
        print(f"\n{'='*60}")
        print(f"SECURITY SCAN SUMMARY")
        print(f"{'='*60}")
        print(f"Target: {results['target']}")
        print(f"Spring Boot Detected: {'Yes' if results['spring_boot_detected'] else 'No'}")
        print(f"Risk Level: {results['risk_level']}")
        
        if results['exposed_safe_endpoints']:
            print(f"\nAccessible Safe Endpoints:")
            for endpoint in results['exposed_safe_endpoints']:
                print(f"  ✓ {endpoint}")
        
        if results['exposed_sensitive_endpoints']:
            print(f"\n⚠️  EXPOSED SENSITIVE ENDPOINTS:")
            for endpoint in results['exposed_sensitive_endpoints']:
                print(f"  ⚠️  {endpoint}")
        
        if results['discovered_endpoints']:
            print(f"\nDiscovered Endpoints (from actuator index):")
            for endpoint in results['discovered_endpoints'][:10]:  # Limit output
                print(f"  • {endpoint}")
            if len(results['discovered_endpoints']) > 10:
                print(f"  ... and {len(results['discovered_endpoints']) - 10} more")
        
        if not results['spring_boot_detected']:
            print("\nUnable to confirm Spring Boot technology. Scan inconclusive.")
        
        print(f"\n{'='*60}")

def main():
    """Main function with argument parsing"""
    parser = argparse.ArgumentParser(
        description='Spring Boot Actuator Security Scanner - Defensive Detection Tool',
        epilog='DISCLAIMER: Use only on systems you own or have explicit permission to test.'
    )
    
    parser.add_argument(
        'targets',
        nargs='+',
        help='Target URLs to scan (e.g., http://example.com)'
    )
    
    parser.add_argument(
        '--timeout',
        type=int,
        default=REQUEST_TIMEOUT,
        help=f'Request timeout in seconds (default: {REQUEST_TIMEOUT})'
    )
    
    parser.add_argument(
        '--max-size',
        type=int,
        default=MAX_RESPONSE_SIZE,
        help=f'Maximum response size in bytes (default: {MAX_RESPONSE_SIZE})'
    )
    
    parser.add_argument(
        '--verbose',
        '-v',
        action='store_true',
        help='Enable verbose logging'
    )
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Validate URLs
    for target in args.targets:
        parsed = urlparse(target)
        if not parsed.scheme or not parsed.netloc:
            print(f"Error: Invalid URL format: {target}")
            sys.exit(1)
    
    print("""
    ╔══════════════════════════════════════════════════════════════════╗
    ║           Spring Boot Actuator Security Scanner                  ║
    ║                    Defensive Detection Tool                      ║
    ╠══════════════════════════════════════════════════════════════════╣
    ║  ⚠️  AUTHORIZED TESTING ONLY ⚠️                                  ║
    ║  This tool performs read-only detection without exploitation.   ║
    ║  Do NOT use on systems without explicit permission.             ║
    ╚══════════════════════════════════════════════════════════════════╝
    """)
    
    scanner = SpringBootActuatorScanner(timeout=args.timeout, max_size=args.max_size)
    
    for target in args.targets:
        try:
            results = scanner.scan_target(target)
            scanner.print_summary(results)
        except KeyboardInterrupt:
            print("\n\nScan interrupted by user. Exiting safely...")
            sys.exit(0)
        except Exception as e:
            logger.error(f"Error scanning {target}: {str(e)}")
            continue
    
    print("\n✅ Scan completed. Remember: Security testing should always be ethical and authorized.")

if __name__ == "__main__":
    main()