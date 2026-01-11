#!/usr/bin/env python3
"""
HTTP Security Header Analyzer
A passive security assessment tool for analyzing HTTP security headers and common misconfigurations.
Author: Security Research Team
Version: 1.0.0
"""

import requests
import json
import sys
import argparse
import urllib3
from urllib.parse import urlparse
from typing import Dict, List, Optional, Tuple
import re
from datetime import datetime

# Disable SSL warnings for testing environments
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class SecurityHeaderAnalyzer:
    """Passive HTTP Security Header Analysis Tool"""
    
    def __init__(self, timeout: int = 10, verify_ssl: bool = False):
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        self.session.verify = verify_ssl
        
        # OWASP Security Headers Reference
        self.security_headers = {
            'strict-transport-security': {
                'name': 'Strict-Transport-Security (HSTS)',
                'description': 'HTTP Strict Transport Security',
                'severity': 'HIGH',
                'owasp_category': 'A05:2021 - Security Misconfiguration',
                'recommendation': 'max-age=31536000; includeSubDomains; preload'
            },
            'content-security-policy': {
                'name': 'Content-Security-Policy (CSP)',
                'description': 'Content Security Policy',
                'severity': 'HIGH',
                'owasp_category': 'A03:2021 - Injection',
                'recommendation': "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'"
            },
            'x-frame-options': {
                'name': 'X-Frame-Options',
                'description': 'Clickjacking Protection',
                'severity': 'MEDIUM',
                'owasp_category': 'A05:2021 - Security Misconfiguration',
                'recommendation': 'DENY or SAMEORIGIN'
            },
            'x-content-type-options': {
                'name': 'X-Content-Type-Options',
                'description': 'MIME Sniffing Protection',
                'severity': 'MEDIUM',
                'owasp_category': 'A05:2021 - Security Misconfiguration',
                'recommendation': 'nosniff'
            },
            'referrer-policy': {
                'name': 'Referrer-Policy',
                'description': 'Referrer Information Control',
                'severity': 'LOW',
                'owasp_category': 'A05:2021 - Security Misconfiguration',
                'recommendation': 'strict-origin-when-cross-origin'
            },
            'permissions-policy': {
                'name': 'Permissions-Policy',
                'description': 'Browser Feature Control',
                'severity': 'LOW',
                'owasp_category': 'A05:2021 - Security Misconfiguration',
                'recommendation': 'Restrict unnecessary features'
            },
            'cross-origin-opener-policy': {
                'name': 'Cross-Origin-Opener-Policy (COOP)',
                'description': 'Cross-Origin Isolation',
                'severity': 'MEDIUM',
                'owasp_category': 'A05:2021 - Security Misconfiguration',
                'recommendation': 'same-origin'
            },
            'cross-origin-resource-policy': {
                'name': 'Cross-Origin-Resource-Policy (CORP)',
                'description': 'Cross-Origin Resource Protection',
                'severity': 'MEDIUM',
                'owasp_category': 'A05:2021 - Security Misconfiguration',
                'recommendation': 'same-origin'
            },
            'cross-origin-embedder-policy': {
                'name': 'Cross-Origin-Embedder-Policy (COEP)',
                'description': 'Cross-Origin Embedding Control',
                'severity': 'MEDIUM',
                'owasp_category': 'A05:2021 - Security Misconfiguration',
                'recommendation': 'require-corp'
            },
            'x-permitted-cross-domain-policies': {
                'name': 'X-Permitted-Cross-Domain-Policies',
                'description': 'Adobe Cross-Domain Policy Control',
                'severity': 'LOW',
                'owasp_category': 'A05:2021 - Security Misconfiguration',
                'recommendation': 'none'
            }
        }
        
        # Information disclosure headers to remove
        self.info_headers = {
            'server', 'x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version',
            'x-generator', 'x-cms', 'x-framework', 'x-php-version', 'x-server',
            'x-turbo-charged-by', 'x-powered-cms', 'x-content-encoded-by',
            'product', 'x-cf-powered-by', 'x-umbraco-version', 'x-joomla-version',
            'x-drupal-cache', 'x-dynatrace', 'x-litespeed-cache', 'x-varnish',
            'x-envoy', 'x-kubernetes', 'x-nextjs', 'x-atmosphere', 'x-b3',
            'x-mod-pagespeed', 'x-page-speed', 'x-cache', 'x-backend'
        }
        
        # CORS headers
        self.cors_headers = {
            'access-control-allow-origin',
            'access-control-allow-methods',
            'access-control-allow-headers',
            'access-control-allow-credentials',
            'access-control-max-age',
            'access-control-expose-headers'
        }

    def analyze_url(self, url: str) -> Dict:
        """Analyze security headers for a given URL"""
        try:
            # Ensure URL has proper scheme
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            
            print(f"[*] Analyzing: {url}")
            
            # Make request
            response = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            
            # Analyze headers
            findings = self._analyze_headers(response.headers, url)
            cookie_findings = self._analyze_cookies(response.cookies)
            cors_findings = self._analyze_cors(response.headers)
            info_disclosure = self._analyze_info_disclosure(response.headers)
            
            return {
                'url': response.url,
                'status_code': response.status_code,
                'redirects': len(response.history),
                'findings': findings,
                'cookie_findings': cookie_findings,
                'cors_findings': cors_findings,
                'info_disclosure': info_disclosure,
                'timestamp': datetime.now().isoformat()
            }
            
        except requests.exceptions.RequestException as e:
            return {
                'url': url,
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }

    def _analyze_headers(self, headers: Dict, url: str) -> List[Dict]:
        """Analyze security headers"""
        findings = []
        header_names = {k.lower(): v for k, v in headers.items()}
        
        # Check for missing critical headers
        for header_key, header_info in self.security_headers.items():
            if header_key not in header_names:
                findings.append({
                    'type': 'missing_header',
                    'header': header_info['name'],
                    'severity': header_info['severity'],
                    'description': f"Missing {header_info['description']} header",
                    'owasp_category': header_info['owasp_category'],
                    'recommendation': f"Add: {header_key}: {header_info['recommendation']}"
                })
            else:
                # Header exists, analyze its value
                value = header_names[header_key]
                specific_findings = self._analyze_specific_header(header_key, value, url)
                findings.extend(specific_findings)
        
        return findings

    def _analyze_specific_header(self, header: str, value: str, url: str) -> List[Dict]:
        """Analyze specific header values for misconfigurations"""
        findings = []
        value_lower = value.lower().strip()
        
        if header == 'strict-transport-security':
            if 'max-age=0' in value_lower:
                findings.append({
                    'type': 'misconfiguration',
                    'header': 'HSTS',
                    'severity': 'HIGH',
                    'description': 'HSTS max-age set to 0 - header is disabled',
                    'owasp_category': 'A05:2021 - Security Misconfiguration',
                    'recommendation': 'Set max-age to at least 31536000 (1 year)'
                })
            elif not re.search(r'max-age=\d+', value):
                findings.append({
                    'type': 'misconfiguration',
                    'header': 'HSTS',
                    'severity': 'HIGH',
                    'description': 'HSTS missing max-age directive',
                    'owasp_category': 'A05:2021 - Security Misconfiguration',
                    'recommendation': 'Add max-age directive, e.g., max-age=31536000'
                })
                
        elif header == 'content-security-policy':
            if "'unsafe-inline'" in value or "'unsafe-eval'" in value:
                findings.append({
                    'type': 'misconfiguration',
                    'header': 'CSP',
                    'severity': 'HIGH',
                    'description': 'CSP allows unsafe-inline or unsafe-eval - XSS protection weakened',
                    'owasp_category': 'A03:2021 - Injection',
                    'recommendation': "Remove 'unsafe-inline' and 'unsafe-eval' directives"
                })
            if 'https:' in value and not 'http:' in value:
                # This is actually good, but let's check for overly permissive policies
                pass
                
        elif header == 'x-frame-options':
            if value_lower not in ['deny', 'sameorigin']:
                findings.append({
                    'type': 'misconfiguration',
                    'header': 'X-Frame-Options',
                    'severity': 'MEDIUM',
                    'description': f'X-Frame-Options set to potentially unsafe value: {value}',
                    'owasp_category': 'A05:2021 - Security Misconfiguration',
                    'recommendation': 'Use DENY or SAMEORIGIN'
                })
                
        elif header == 'referrer-policy':
            unsafe_values = ['unsafe-url', 'no-referrer-when-downgrade']
            if any(unsafe in value_lower for unsafe in unsafe_values):
                findings.append({
                    'type': 'misconfiguration',
                    'header': 'Referrer-Policy',
                    'severity': 'LOW',
                    'description': f'Referrer-Policy allows information leakage: {value}',
                    'owasp_category': 'A05:2021 - Security Misconfiguration',
                    'recommendation': 'Use strict-origin-when-cross-origin or no-referrer'
                })
        
        return findings

    def _analyze_cookies(self, cookies) -> List[Dict]:
        """Analyze cookie security attributes"""
        findings = []
        
        for cookie in cookies:
            cookie_str = str(cookie)
            
            # Check for missing HttpOnly
            if 'httponly' not in cookie_str.lower():
                findings.append({
                    'type': 'cookie_security',
                    'cookie': cookie.name,
                    'severity': 'HIGH',
                    'description': f"Cookie '{cookie.name}' missing HttpOnly flag",
                    'owasp_category': 'A05:2021 - Security Misconfiguration',
                    'recommendation': 'Add HttpOnly flag to prevent XSS cookie theft'
                })
            
            # Check for missing Secure flag
            if 'secure' not in cookie_str.lower():
                findings.append({
                    'type': 'cookie_security',
                    'cookie': cookie.name,
                    'severity': 'HIGH',
                    'description': f"Cookie '{cookie.name}' missing Secure flag",
                    'owasp_category': 'A05:2021 - Security Misconfiguration',
                    'recommendation': 'Add Secure flag to prevent transmission over HTTP'
                })
            
            # Check for missing SameSite
            if 'samesite' not in cookie_str.lower():
                findings.append({
                    'type': 'cookie_security',
                    'cookie': cookie.name,
                    'severity': 'MEDIUM',
                    'description': f"Cookie '{cookie.name}' missing SameSite attribute",
                    'owasp_category': 'A05:2021 - Security Misconfiguration',
                    'recommendation': 'Add SameSite=Strict to prevent CSRF attacks'
                })
        
        return findings

    def _analyze_cors(self, headers: Dict) -> List[Dict]:
        """Analyze CORS configuration"""
        findings = []
        header_names = {k.lower(): v for k, v in headers.items()}
        
        # Check for insecure CORS configuration
        if 'access-control-allow-origin' in header_names:
            acao_value = header_names['access-control-allow-origin'].lower()
            
            if acao_value == '*':
                findings.append({
                    'type': 'cors_misconfiguration',
                    'header': 'Access-Control-Allow-Origin',
                    'severity': 'HIGH',
                    'description': 'CORS allows all origins (*) - potential security risk',
                    'owasp_category': 'A05:2021 - Security Misconfiguration',
                    'recommendation': 'Restrict to specific trusted origins'
                })
            
            # Check for credentials with wildcard
            if 'access-control-allow-credentials' in header_names:
                acac_value = header_names['access-control-allow-credentials'].lower()
                if acao_value == '*' and acac_value == 'true':
                    findings.append({
                        'type': 'cors_misconfiguration',
                        'header': 'CORS',
                        'severity': 'CRITICAL',
                        'description': 'CORS allows credentials with wildcard origin - CSRF risk',
                        'owasp_category': 'A05:2021 - Security Misconfiguration',
                        'recommendation': 'Never allow credentials with wildcard origin'
                    })
        
        return findings

    def _analyze_info_disclosure(self, headers: Dict) -> List[Dict]:
        """Analyze information disclosure headers"""
        findings = []
        
        for header_name, header_value in headers.items():
            header_lower = header_name.lower()
            
            if header_lower in self.info_headers:
                findings.append({
                    'type': 'information_disclosure',
                    'header': header_name,
                    'severity': 'LOW',
                    'description': f"Information disclosure via {header_name} header: {header_value}",
                    'owasp_category': 'A05:2021 - Security Misconfiguration',
                    'recommendation': f'Remove {header_name} header to prevent technology fingerprinting'
                })
        
        return findings

    def generate_report(self, results: Dict) -> str:
        """Generate a formatted security report"""
        if 'error' in results:
            return f"[!] Error analyzing {results['url']}: {results['error']}"
        
        report = []
        report.append("=" * 80)
        report.append("HTTP SECURITY HEADER ANALYSIS REPORT")
        report.append("=" * 80)
        report.append(f"URL: {results['url']}")
        report.append(f"Status Code: {results['status_code']}")
        report.append(f"Redirects: {results['redirects']}")
        report.append(f"Analysis Time: {results['timestamp']}")
        report.append("")
        
        # Critical findings first
        all_findings = []
        all_findings.extend(results['findings'])
        all_findings.extend(results['cookie_findings'])
        all_findings.extend(results['cors_findings'])
        all_findings.extend(results['info_disclosure'])
        
        if not all_findings:
            report.append("[+] No security header issues found!")
            return "\n".join(report)
        
        # Sort by severity
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        all_findings.sort(key=lambda x: severity_order.get(x['severity'], 4))
        
        # Group by severity
        current_severity = None
        for finding in all_findings:
            if finding['severity'] != current_severity:
                current_severity = finding['severity']
                report.append(f"\n[{finding['severity']}] SEVERITY FINDINGS:")
                report.append("-" * 50)
            
            report.append(f"Type: {finding['type'].replace('_', ' ').title()}")
            report.append(f"Description: {finding['description']}")
            report.append(f"OWASP Category: {finding['owasp_category']}")
            report.append(f"Recommendation: {finding['recommendation']}")
            report.append("")
        
        # Summary
        report.append("SECURITY SUMMARY:")
        report.append("-" * 30)
        severity_counts = {}
        for finding in all_findings:
            severity = finding['severity']
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            if severity in severity_counts:
                report.append(f"{severity}: {severity_counts[severity]} findings")
        
        return "\n".join(report)

    def generate_json_report(self, results: Dict) -> str:
        """Generate JSON format report"""
        return json.dumps(results, indent=2, default=str)

def main():
    parser = argparse.ArgumentParser(description='HTTP Security Header Analyzer')
    parser.add_argument('url', help='Target URL to analyze')
    parser.add_argument('-j', '--json', action='store_true', help='Output in JSON format')
    parser.add_argument('-t', '--timeout', type=int, default=10, help='Request timeout (default: 10)')
    parser.add_argument('--verify-ssl', action='store_true', help='Verify SSL certificates')
    
    args = parser.parse_args()
    
    # Initialize analyzer
    analyzer = SecurityHeaderAnalyzer(timeout=args.timeout, verify_ssl=args.verify_ssl)
    
    # Analyze URL
    print(f"[*] Starting security header analysis...")
    results = analyzer.analyze_url(args.url)
    
    # Generate report
    if args.json:
        print(analyzer.generate_json_report(results))
    else:
        print(analyzer.generate_report(results))

if __name__ == '__main__':
    main()