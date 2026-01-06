"""OWASP Top 10 Pattern Detector - Passive Analysis Only"""
import aiohttp
import re
from typing import Dict, List
import logging
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

class OWASPDetector:
    """Detect OWASP Top 10 patterns through passive analysis"""
    
    def __init__(self, target: str, scan_results: Dict):
        self.target = target
        self.scan_results = scan_results
    
    async def detect(self) -> List[Dict]:
        """Detect OWASP Top 10 patterns"""
        vulnerabilities = []
        
        try:
            # Normalize URL
            if "://" not in self.target:
                url = f"https://{self.target}"
            else:
                url = self.target
            
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=8, connect=3),
                connector=aiohttp.TCPConnector(limit=10)
            ) as session:
                try:
                    async with session.get(base_url, timeout=aiohttp.ClientTimeout(total=8), allow_redirects=True, ssl=False) as resp:
                        content = await resp.text()
                        headers = resp.headers
                        
                        # A01:2021 - Broken Access Control
                        vulnerabilities.extend(self._check_access_control(headers, resp.status))
                        
                        # A02:2021 - Cryptographic Failures
                        vulnerabilities.extend(self._check_cryptographic_failures(headers))
                        
                        # A03:2021 - Injection (passive detection)
                        vulnerabilities.extend(self._check_injection_patterns(content, headers))
                        
                        # A05:2021 - Security Misconfiguration
                        vulnerabilities.extend(self._check_misconfiguration(headers, self.scan_results))
                        
                        # A07:2021 - Identification and Authentication Failures
                        vulnerabilities.extend(self._check_auth_failures(headers))
                        
                except Exception as e:
                    logger.warning(f"OWASP detection error: {e}")
        
        except Exception as e:
            logger.error(f"OWASP detector error: {e}")
        
        return vulnerabilities
    
    def _check_access_control(self, headers: dict, status_code: int) -> List[Dict]:
        """Check for broken access control indicators"""
        vulns = []
        
        # Check for directory listing
        if status_code == 200 and "index of" in headers.get("Content-Type", "").lower():
            vulns.append({
                "type": "broken_access_control",
                "severity": "medium",
                "owasp": "A01:2021",
                "issue": "Potential directory listing enabled",
                "recommendation": "Disable directory listing in web server configuration"
            })
        
        return vulns
    
    def _check_cryptographic_failures(self, headers: dict) -> List[Dict]:
        """Check for cryptographic failures"""
        vulns = []
        
        # Check for HTTP (not HTTPS) usage
        if "Strict-Transport-Security" not in headers:
            vulns.append({
                "type": "cryptographic_failure",
                "severity": "high",
                "owasp": "A02:2021",
                "issue": "Missing HSTS header - sensitive data may be transmitted over HTTP",
                "recommendation": "Implement HSTS and enforce HTTPS"
            })
        
        return vulns
    
    def _check_injection_patterns(self, content: str, headers: dict) -> List[Dict]:
        """Passive detection of potential injection vulnerabilities"""
        vulns = []
        
        # Check for SQL error messages (indicates potential SQL injection)
        sql_errors = [
            "mysql_fetch",
            "ORA-",
            "PostgreSQL query failed",
            "SQL syntax",
            "Microsoft OLE DB Provider"
        ]
        
        for error in sql_errors:
            if error.lower() in content.lower():
                vulns.append({
                    "type": "injection",
                    "severity": "high",
                    "owasp": "A03:2021",
                    "issue": f"Potential SQL injection vulnerability - database error exposed: {error}",
                    "recommendation": "Implement parameterized queries and proper error handling"
                })
                break
        
        # Check for XSS indicators
        if re.search(r'<script[^>]*>.*</script>', content, re.IGNORECASE):
            if "Content-Security-Policy" not in headers:
                vulns.append({
                    "type": "xss",
                    "severity": "medium",
                    "owasp": "A03:2021",
                    "issue": "Potential XSS vulnerability - inline scripts detected without CSP",
                    "recommendation": "Implement Content Security Policy and sanitize user input"
                })
        
        return vulns
    
    def _check_misconfiguration(self, headers: dict, scan_results: Dict) -> List[Dict]:
        """Check for security misconfigurations"""
        vulns = []
        
        # Server version disclosure
        if "Server" in headers:
            server = headers["Server"]
            if any(x in server.lower() for x in ["apache/", "nginx/", "iis/", "microsoft"]):
                vulns.append({
                    "type": "misconfiguration",
                    "severity": "low",
                    "owasp": "A05:2021",
                    "issue": f"Server version disclosed: {server}",
                    "recommendation": "Hide server version information"
                })
        
        # X-Powered-By disclosure
        if "X-Powered-By" in headers:
            vulns.append({
                "type": "misconfiguration",
                "severity": "low",
                "owasp": "A05:2021",
                "issue": f"Technology stack disclosed: {headers['X-Powered-By']}",
                "recommendation": "Remove X-Powered-By header"
            })
        
        # Default credentials / default pages
        default_pages = ["/admin", "/administrator", "/phpmyadmin", "/wp-admin"]
        # This would require additional requests - keeping passive for now
        
        return vulns
    
    def _check_auth_failures(self, headers: dict) -> List[Dict]:
        """Check for authentication and session management failures"""
        vulns = []
        
        # Check for session fixation
        if "Set-Cookie" in headers:
            cookie = headers["Set-Cookie"]
            if "HttpOnly" not in cookie:
                vulns.append({
                    "type": "auth_failure",
                    "severity": "medium",
                    "owasp": "A07:2021",
                    "issue": "Session cookie missing HttpOnly flag",
                    "recommendation": "Set HttpOnly flag on session cookies"
                })
            if "Secure" not in cookie and "https://" in self.target:
                vulns.append({
                    "type": "auth_failure",
                    "severity": "high",
                    "owasp": "A07:2021",
                    "issue": "Session cookie missing Secure flag over HTTPS",
                    "recommendation": "Set Secure flag on session cookies"
                })
        
        return vulns

