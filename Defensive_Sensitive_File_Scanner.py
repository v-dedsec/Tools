#!/usr/bin/env python3
"""
Ethical Sensitive File Scanner
A defensive security tool for detecting publicly accessible sensitive files
Author: Security Researcher
Version: 1.0.0
"""

import argparse
import asyncio
import aiohttp
import ssl
import sys
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse
import time

class SensitiveFileScanner:
    """Defensive scanner for detecting publicly accessible sensitive files"""
    
    # Target sensitive files for existence checking only
    SENSITIVE_FILES = [
        '.env',
        '.git/config',
        'backup.zip',
        'config.yml',
        'database.sql'
    ]
    
    # Risk levels based on file sensitivity
    RISK_LEVELS = {
        '.env': 'CRITICAL',
        '.git/config': 'HIGH',
        'backup.zip': 'CRITICAL',
        'config.yml': 'HIGH',
        'database.sql': 'CRITICAL'
    }
    
    def __init__(self, base_url: str, timeout: int = 10, max_size: int = 1024):
        """
        Initialize the scanner
        
        Args:
            base_url: Base URL to scan
            timeout: Request timeout in seconds
            max_size: Maximum response size in bytes (default: 1KB)
        """
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.max_size = max_size
        self.session = None
        self.findings = []
        
    async def __aenter__(self):
        """Async context manager entry"""
        connector = aiohttp.TCPConnector(
            ssl=False,  # Allow self-signed certificates for research
            limit=10,
            limit_per_host=5
        )
        
        timeout = aiohttp.ClientTimeout(
            total=self.timeout,
            connect=5,
            sock_read=5
        )
        
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={
                'User-Agent': 'SecurityResearch-Scanner/1.0 (Ethical-Research)',
                'Accept': '*/*',
                'Connection': 'close'
            }
        )
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()
    
    def _get_file_url(self, file_path: str) -> str:
        """Construct full URL for sensitive file"""
        return urljoin(f"{self.base_url}/", file_path)
    
    def _assess_risk(self, status_code: int, content_type: str, file_path: str) -> str:
        """Assess risk level based on response characteristics"""
        base_risk = self.RISK_LEVELS.get(file_path, 'MEDIUM')
        
        # Increase risk if file appears to be accessible
        if status_code == 200:
            if 'text/plain' in content_type or 'application/octet-stream' in content_type:
                return f"{base_risk}-EXPOSED"
            return f"{base_risk}-ACCESSIBLE"
        elif status_code == 403:
            return f"{base_risk}-FORBIDDEN"
        elif status_code == 404:
            return "LOW-NOT_FOUND"
        
        return base_risk
    
    async def _check_file(self, file_path: str) -> Optional[Dict]:
        """
        Check if sensitive file is publicly accessible
        
        Returns:
            Dict with findings or None if check failed
        """
        url = self._get_file_url(file_path)
        
        try:
            # Use HEAD request to avoid downloading content
            async with self.session.head(
                url,
                allow_redirects=False,
                max_redirects=0
            ) as response:
                
                # Early abort if response is too large (safety check)
                content_length = response.headers.get('Content-Length')
                if content_length and int(content_length) > self.max_size:
                    return {
                        'file_path': file_path,
                        'url': url,
                        'status_code': response.status,
                        'content_type': response.headers.get('Content-Type', 'unknown'),
                        'content_length': content_length,
                        'risk_level': 'CRITICAL-LARGE_FILE',
                        'timestamp': time.time()
                    }
                
                risk_level = self._assess_risk(
                    response.status,
                    response.headers.get('Content-Type', 'unknown'),
                    file_path
                )
                
                finding = {
                    'file_path': file_path,
                    'url': url,
                    'status_code': response.status,
                    'content_type': response.headers.get('Content-Type', 'unknown'),
                    'content_length': content_length,
                    'risk_level': risk_level,
                    'server': response.headers.get('Server', 'unknown'),
                    'timestamp': time.time()
                }
                
                return finding
                
        except asyncio.TimeoutError:
            return {
                'file_path': file_path,
                'url': url,
                'status_code': 'TIMEOUT',
                'content_type': 'unknown',
                'risk_level': 'ERROR-TIMEOUT',
                'timestamp': time.time()
            }
        except aiohttp.ClientError as e:
            return {
                'file_path': file_path,
                'url': url,
                'status_code': 'ERROR',
                'content_type': 'unknown',
                'risk_level': f'ERROR-{str(e)[:50]}',
                'timestamp': time.time()
            }
        except Exception as e:
            return {
                'file_path': file_path,
                'url': url,
                'status_code': 'ERROR',
                'content_type': 'unknown',
                'risk_level': f'ERROR-{type(e).__name__}',
                'timestamp': time.time()
            }
    
    async def scan(self) -> List[Dict]:
        """
        Perform defensive scan for sensitive files
        
        Returns:
            List of findings
        """
        print(f"🔍 Starting defensive scan for: {self.base_url}")
        print(f"📋 Target files: {', '.join(self.SENSITIVE_FILES)}")
        print("⚡ Using HEAD requests only (no content download)")
        print("🛡️  Max response size: 1KB")
        print("=" * 60)
        
        findings = []
        
        for file_path in self.SENSITIVE_FILES:
            print(f"Checking: {file_path}", end=" ", flush=True)
            
            finding = await self._check_file(file_path)
            if finding:
                findings.append(finding)
                
                # Display result
                status = finding['status_code']
                risk = finding['risk_level']
                content_type = finding['content_type']
                
                # Color-coded output based on risk
                if 'CRITICAL' in risk or 'EXPOSED' in risk:
                    print(f"❌ {status} - {risk}")
                elif 'HIGH' in risk:
                    print(f"⚠️  {status} - {risk}")
                elif 'ACCESSIBLE' in risk:
                    print(f"🔍 {status} - {risk}")
                else:
                    print(f"✅ {status} - {risk}")
                
                # Stop immediately if sensitive file is exposed
                if status == 200 and 'EXPOSED' in risk:
                    print(f"\n🚨 CRITICAL: Sensitive file exposed!")
                    print(f"   File: {finding['file_path']}")
                    print(f"   URL: {finding['url']}")
                    print(f"   Content-Type: {content_type}")
                    print("   ⚡ Stopping scan immediately...")
                    break
            else:
                print("❓ Check failed")
        
        print("=" * 60)
        return findings
    
    def generate_report(self, findings: List[Dict]) -> str:
        """Generate security assessment report"""
        report = []
        report.append("🔒 SENSITIVE FILE SCAN REPORT")
        report.append("=" * 50)
        report.append(f"Target: {self.base_url}")
        report.append(f"Scan Time: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}")
        report.append(f"Total Files Checked: {len(self.SENSITIVE_FILES)}")
        report.append(f"Findings: {len(findings)}")
        report.append("")
        
        if not findings:
            report.append("✅ No sensitive files detected")
        else:
            report.append("📋 FINDINGS:")
            for finding in findings:
                report.append(f"\nFile: {finding['file_path']}")
                report.append(f"  URL: {finding['url']}")
                report.append(f"  Status: {finding['status_code']}")
                report.append(f"  Content-Type: {finding['content_type']}")
                report.append(f"  Risk Level: {finding['risk_level']}")
                if finding.get('content_length'):
                    report.append(f"  Size: {finding['content_length']} bytes")
        
        report.append("\n" + "=" * 50)
        report.append("⚠️  DISCLAIMER: This scan is for defensive security assessment only.")
        report.append("   All checks are read-only with no content parsing or downloading.")
        
        return "\n".join(report)

async def main():
    """Main execution function"""
    parser = argparse.ArgumentParser(
        description="Ethical Sensitive File Scanner - Defensive Security Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 sensitive_scanner.py https://example.com
  python3 sensitive_scanner.py https://api.example.com --timeout 15

⚠️  ETHICAL USE ONLY:
   - Only performs HEAD requests (no content download)
   - Stops immediately on sensitive file detection
   - Max 1KB response size enforced
   - For defensive security research only
        """
    )
    
    parser.add_argument(
        'url',
        help='Base URL to scan (e.g., https://example.com)'
    )
    
    parser.add_argument(
        '--timeout',
        type=int,
        default=10,
        help='Request timeout in seconds (default: 10)'
    )
    
    parser.add_argument(
        '--max-size',
        type=int,
        default=1024,
        help='Maximum response size in bytes (default: 1024)'
    )
    
    parser.add_argument(
        '--output',
        type=str,
        help='Output file for report (optional)'
    )
    
    args = parser.parse_args()
    
    # Validate URL
    try:
        parsed = urlparse(args.url)
        if not parsed.scheme or not parsed.netloc:
            print("❌ Invalid URL format. Use: https://example.com")
            sys.exit(1)
    except Exception:
        print("❌ Invalid URL format")
        sys.exit(1)
    
    # Run scan
    try:
        async with SensitiveFileScanner(
            base_url=args.url,
            timeout=args.timeout,
            max_size=args.max_size
        ) as scanner:
            
            findings = await scanner.scan()
            report = scanner.generate_report(findings)
            
            # Display report
            print("\n" + report)
            
            # Save report if requested
            if args.output:
                with open(args.output, 'w') as f:
                    f.write(report)
                print(f"\n📄 Report saved to: {args.output}")
            
            # Exit with appropriate code
            if any('EXPOSED' in f.get('risk_level', '') for f in findings):
                sys.exit(2)  # Critical findings
            elif findings:
                sys.exit(1)  # Non-critical findings
            else:
                sys.exit(0)  # Clean scan
                
    except KeyboardInterrupt:
        print("\n\n⚠️  Scan interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n❌ Scan failed: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())