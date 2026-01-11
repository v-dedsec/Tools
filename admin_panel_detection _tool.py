#!/usr/bin/env python3
"""
Admin Panel Detector - Read-only Security Research Tool
Author: Security Research Tool
Description: Detects potentially exposed administrative panels through passive reconnaissance only.
No login attempts, brute forcing, or authenticated area access.

Safety Constraints:
- Only performs HEAD/GET requests
- No credential submission
- No form interaction
- No brute force attempts
- Respects rate limits
"""

import requests
import argparse
import time
import re
from urllib.parse import urljoin, urlparse
from typing import List, Dict, Optional
import json
from datetime import datetime
import colorama
from colorama import Fore, Style

# Initialize colorama for cross-platform colored output
colorama.init(autoreset=True)

class AdminPanelDetector:
    """Read-only admin panel detection tool for security research"""
    
    def __init__(self, delay: float = 1.0, timeout: int = 10, user_agent: str = None):
        """
        Initialize the detector with safety settings
        
        Args:
            delay: Delay between requests (seconds)
            timeout: Request timeout (seconds)
            user_agent: Custom user agent string
        """
        self.delay = delay
        self.timeout = timeout
        self.session = requests.Session()
        
        # Set browser-like headers to avoid detection
        self.session.headers.update({
            'User-Agent': user_agent or 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
        
        # Common admin paths (extensive but safe list)
        self.admin_paths = [
            # Standard admin paths
            'admin', 'administrator', 'administration', 'adminpanel', 'admincp',
            'controlpanel', 'control', 'cpanel', 'panel', 'manage', 'management',
            'dashboard', 'backend', 'console', 'portal', 'webadmin',
            
            # CMS specific (safe detection only)
            'wp-admin', 'wp-login', 'administrator', 'admin1', 'admin2',
            'admin123', 'administrator', 'moderator', 'webadmin', 'adminarea',
            'bb-admin', 'adminLogin', 'admin_area', 'panel-administracion',
            'instadmin', 'memberadmin', 'administratorlogin', 'adm', 'admincp',
            'admin_login', 'admin-account', 'admincontrol', 'adminitems',
            'adminitem', 'administration', 'adminuser', 'adminusers',
            'administratorlogin', 'administrator.php', 'admin.php', 'admin.html',
            
            # Application specific
            'phpmyadmin', 'mysql', 'database', 'dbadmin', 'sqladmin',
            'server', 'serveradmin', 'sysadmin', 'root', 'webmaster',
            'postmaster', 'mailadmin', 'emailadmin', 'ftp', 'sftp',
            
            # Common variations
            'adm', 'account', 'accounts', 'auth', 'authentication',
            'authorize', 'authorization', 'access', 'accesscontrol',
            'superuser', 'superadmin', 'boss', 'master', 'root',
            
            # Hidden/backup admin paths
            'hidden', 'backup', 'old', 'test', 'dev', 'development',
            'staging', 'demo', 'temp', 'tmp', 'private', 'secure',
            
            # Framework specific (detection only)
            'django-admin', 'admin/auth/user', 'rails_admin', 'activeadmin',
            'adminer', 'phpminiadmin', 'bigdump', 'mysql-admin',
            
            # Modern admin paths
            'api/admin', 'v1/admin', 'v2/admin', 'admin/api',
            'management/api', 'console/api', 'backend/api'
        ]
        
        # Keywords that indicate admin interfaces
        self.admin_keywords = [
            'admin', 'administrator', 'login', 'dashboard', 'control panel',
            'management', 'backend', 'console', 'portal', 'authentication',
            'authorization', 'secure', 'private', 'cpanel', 'webadmin'
        ]
        
        # Security headers that indicate protection level
        self.security_headers = [
            'X-Frame-Options', 'X-Content-Type-Options', 'X-XSS-Protection',
            'Strict-Transport-Security', 'Content-Security-Policy',
            'Referrer-Policy', 'Permissions-Policy', 'X-Permitted-Cross-Domain-Policies'
        ]
    
    def detect_admin_indicators(self, content: str, title: str, headers: Dict) -> Dict:
        """
        Detect admin interface indicators from content, title, and headers
        
        Returns:
            Dict with confidence score and indicators found
        """
        indicators = {
            'confidence': 0,
            'title_indicators': [],
            'content_indicators': [],
            'header_indicators': [],
            'access_level': 'unknown',
            'risk_level': 'low'
        }
        
        # Check page title
        title_lower = title.lower()
        for keyword in self.admin_keywords:
            if keyword in title_lower:
                indicators['title_indicators'].append(keyword)
                indicators['confidence'] += 20
        
        # Check page content (basic patterns only)
        content_lower = content.lower()[:2000]  # Limit content check to first 2000 chars
        admin_patterns = [
            r'administrator', r'login.*admin', r'admin.*login',
            r'control.*panel', r'management.*console', r'admin.*dashboard',
            r'username', r'password', r'authentication', r'authorization'
        ]
        
        for pattern in admin_patterns:
            if re.search(pattern, content_lower, re.IGNORECASE):
                indicators['content_indicators'].append(pattern)
                indicators['confidence'] += 15
        
        # Check headers for admin indicators
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
        for header_name, header_value in headers_lower.items():
            if any(keyword in header_value for keyword in ['admin', 'login', 'dashboard']):
                indicators['header_indicators'].append(f"{header_name}: {header_value}")
                indicators['confidence'] += 10
        
        # Determine access level
        if 'location' in headers_lower and any(word in headers_lower['location'] for word in ['login', 'auth']):
            indicators['access_level'] = 'protected'
            indicators['confidence'] += 10
        elif indicators['confidence'] > 30:
            indicators['access_level'] = 'public'
        else:
            indicators['access_level'] = 'unknown'
        
        # Risk classification
        if indicators['confidence'] >= 70:
            indicators['risk_level'] = 'high'
        elif indicators['confidence'] >= 40:
            indicators['risk_level'] = 'medium'
        else:
            indicators['risk_level'] = 'low'
        
        return indicators
    
    def check_security_headers(self, headers: Dict) -> Dict:
        """Analyze security headers to assess protection level"""
        security_analysis = {
            'present': [],
            'missing': [],
            'protection_level': 'unknown'
        }
        
        for header in self.security_headers:
            if header in headers:
                security_analysis['present'].append(header)
            else:
                security_analysis['missing'].append(header)
        
        # Determine protection level
        present_count = len(security_analysis['present'])
        if present_count >= 6:
            security_analysis['protection_level'] = 'high'
        elif present_count >= 3:
            security_analysis['protection_level'] = 'medium'
        else:
            security_analysis['protection_level'] = 'low'
        
        return security_analysis
    
    def check_single_path(self, base_url: str, path: str) -> Optional[Dict]:
        """
        Check a single admin path safely
        
        Returns:
            Dict with detection results or None if no admin indicators found
        """
        url = urljoin(base_url, path)
        
        try:
            # Use HEAD request first (safer)
            head_response = self.session.head(
                url, 
                timeout=self.timeout,
                allow_redirects=True,
                verify=True  # Verify SSL certificates
            )
            
            # If HEAD is not allowed, use GET with safety measures
            if head_response.status_code == 405:  # Method Not Allowed
                response = self.session.get(
                    url,
                    timeout=self.timeout,
                    allow_redirects=True,
                    verify=True,
                    stream=True  # Don't download entire content
                )
                # Limit content reading for safety
                content = ''
                try:
                    for chunk in response.iter_content(chunk_size=1024, decode_unicode=True):
                        if len(content) < 2000:  # Limit content to first 2000 chars
                            content += chunk
                        else:
                            break
                except:
                    content = ''
            else:
                response = head_response
                content = ''
            
            # Extract title from content if available
            title_match = re.search(r'<title[^>]*>([^<]+)</title>', content, re.IGNORECASE)
            title = title_match.group(1).strip() if title_match else 'No Title'
            
            # Detect admin indicators
            indicators = self.detect_admin_indicators(content, title, dict(response.headers))
            
            # Check security headers
            security_analysis = self.check_security_headers(dict(response.headers))
            
            if indicators['confidence'] > 20:  # Only report if confidence is significant
                return {
                    'url': url,
                    'status_code': response.status_code,
                    'title': title,
                    'admin_detected': True,
                    'confidence': indicators['confidence'],
                    'indicators': indicators,
                    'security_analysis': security_analysis,
                    'timestamp': datetime.now().isoformat()
                }
            
            return None
            
        except requests.exceptions.RequestException as e:
            # Silently handle connection errors (site might be down, etc.)
            return None
        except Exception as e:
            # Handle any other unexpected errors gracefully
            return None
        finally:
            # Ensure we always wait between requests
            time.sleep(self.delay)
    
    def scan_target(self, target_url: str) -> List[Dict]:
        """
        Scan a target URL for admin panels
        
        Returns:
            List of detection results
        """
        results = []
        
        # Normalize URL
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'https://' + target_url
        
        # Parse URL to ensure it's valid
        try:
            parsed = urlparse(target_url)
            if not parsed.netloc:
                print(f"{Fore.RED}[ERROR] Invalid URL: {target_url}{Style.RESET_ALL}")
                return results
        except:
            print(f"{Fore.RED}[ERROR] Invalid URL format: {target_url}{Style.RESET_ALL}")
            return results
        
        print(f"{Fore.BLUE}[INFO] Starting admin panel detection for: {target_url}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[WARNING] This tool performs read-only detection only. No login attempts will be made.{Style.RESET_ALL}")
        
        # Test each admin path
        for i, path in enumerate(self.admin_paths, 1):
            print(f"{Fore.CYAN}[SCAN] Checking path {i}/{len(self.admin_paths)}: /{path}{Style.RESET_ALL}", end='\r')
            
            result = self.check_single_path(target_url, path)
            if result:
                results.append(result)
                print(f"{Fore.GREEN}[FOUND] Admin panel detected: {result['url']} (Confidence: {result['confidence']}%) {Style.RESET_ALL}")
        
        print(f"\n{Fore.BLUE}[INFO] Scan completed. Found {len(results)} potential admin panels.{Style.RESET_ALL}")
        return results
    
    def generate_report(self, results: List[Dict], output_file: str = None):
        """Generate a detailed report of findings"""
        report = {
            'scan_metadata': {
                'tool': 'Admin Panel Detector (Read-only)',
                'version': '1.0.0',
                'scan_date': datetime.now().isoformat(),
                'total_paths_checked': len(self.admin_paths),
                'findings_count': len(results)
            },
            'findings': results,
            'summary': {
                'high_risk': len([r for r in results if r['indicators']['risk_level'] == 'high']),
                'medium_risk': len([r for r in results if r['indicators']['risk_level'] == 'medium']),
                'low_risk': len([r for r in results if r['indicators']['risk_level'] == 'low']),
                'public_access': len([r for r in results if r['indicators']['access_level'] == 'public']),
                'protected_access': len([r for r in results if r['indicators']['access_level'] == 'protected']),
                'unknown_access': len([r for r in results if r['indicators']['access_level'] == 'unknown'])
            }
        }
        
        # Display summary
        print(f"\n{Fore.BLUE}{'='*60}")
        print(f"{Fore.BLUE}SECURITY RESEARCH REPORT{Style.RESET_ALL}")
        print(f"{Fore.BLUE}{'='*60}{Style.RESET_ALL}")
        print(f"Scan Date: {report['scan_metadata']['scan_date']}")
        print(f"Total Paths Checked: {report['scan_metadata']['total_paths_checked']}")
        print(f"Admin Panels Detected: {report['scan_metadata']['findings_count']}")
        print(f"\nRisk Classification:")
        print(f"  High Risk: {report['summary']['high_risk']}")
        print(f"  Medium Risk: {report['summary']['medium_risk']}")
        print(f"  Low Risk: {report['summary']['low_risk']}")
        print(f"\nAccess Levels:")
        print(f"  Public: {report['summary']['public_access']}")
        print(f"  Protected: {report['summary']['protected_access']}")
        print(f"  Unknown: {report['summary']['unknown_access']}")
        
        if results:
            print(f"\n{Fore.YELLOW}Detailed Findings:{Style.RESET_ALL}")
            for i, finding in enumerate(results, 1):
                risk_color = Fore.RED if finding['indicators']['risk_level'] == 'high' else Fore.YELLOW if finding['indicators']['risk_level'] == 'medium' else Fore.GREEN
                access_color = Fore.RED if finding['indicators']['access_level'] == 'public' else Fore.YELLOW
                
                print(f"\n{i}. {risk_color}URL: {finding['url']}{Style.RESET_ALL}")
                print(f"   Status Code: {finding['status_code']}")
                print(f"   Title: {finding['title']}")
                print(f"   Confidence: {finding['confidence']}%")
                print(f"   Risk Level: {risk_color}{finding['indicators']['risk_level'].upper()}{Style.RESET_ALL}")
                print(f"   Access Level: {access_color}{finding['indicators']['access_level'].upper()}{Style.RESET_ALL}")
                
                if finding['indicators']['title_indicators']:
                    print(f"   Title Indicators: {', '.join(finding['indicators']['title_indicators'])}")
                if finding['indicators']['content_indicators']:
                    print(f"   Content Indicators: {len(finding['indicators']['content_indicators'])} patterns found")
                
                print(f"   Security Headers: {finding['security_analysis']['protection_level']} protection")
        
        # Save to file if requested
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            print(f"\n{Fore.GREEN}[SAVED] Report saved to: {output_file}{Style.RESET_ALL}")
        
        return report

def main():
    """Main function with argument parsing"""
    parser = argparse.ArgumentParser(
        description='Admin Panel Detector - Read-only Security Research Tool',
        epilog='This tool performs passive reconnaissance only. No login attempts or brute forcing.',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('urls', nargs='+', help='Target URLs to scan')
    parser.add_argument('--delay', type=float, default=1.0, help='Delay between requests (seconds)')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout (seconds)')
    parser.add_argument('--output', '-o', help='Output file for JSON report')
    parser.add_argument('--user-agent', help='Custom User-Agent string')
    parser.add_argument('--rate-limit', type=float, help='Rate limit (requests per second)')
    
    args = parser.parse_args()
    
    # Create detector instance
    detector = AdminPanelDetector(
        delay=args.delay,
        timeout=args.timeout,
        user_agent=args.user_agent
    )
    
    # Adjust delay based on rate limit if specified
    if args.rate_limit:
        detector.delay = max(1.0 / args.rate_limit, args.delay)
    
    all_results = []
    
    # Scan each target
    for url in args.urls:
        try:
            results = detector.scan_target(url)
            all_results.extend(results)
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[INTERRUPTED] Scan interrupted by user{Style.RESET_ALL}")
            break
        except Exception as e:
            print(f"{Fore.RED}[ERROR] Failed to scan {url}: {str(e)}{Style.RESET_ALL}")
    
    # Generate report
    if all_results:
        detector.generate_report(all_results, args.output)
    else:
        print(f"\n{Fore.YELLOW}[INFO] No admin panels detected during this scan.{Style.RESET_ALL}")
    
    print(f"\n{Fore.BLUE}[INFO] Security research scan completed.{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[DISCLAIMER] This tool is for authorized security research only. Always follow responsible disclosure practices.{Style.RESET_ALL}")

if __name__ == '__main__':
    main()