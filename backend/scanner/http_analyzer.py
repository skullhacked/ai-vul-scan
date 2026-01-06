"""HTTP Security Headers Analyzer"""
import aiohttp
from typing import Dict, List
import logging
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

class HTTPAnalyzer:
    """Analyze HTTP security headers and configurations"""
    
    SECURITY_HEADERS = [
        "Strict-Transport-Security",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "X-XSS-Protection",
        "Content-Security-Policy",
        "Referrer-Policy",
        "Permissions-Policy",
        "X-Permitted-Cross-Domain-Policies"
    ]
    
    def __init__(self, target: str):
        self.target = target
    
    async def analyze(self) -> Dict:
        """Analyze HTTP security headers"""
        results = {
            "headers": {},
            "missing_headers": [],
            "vulnerabilities": []
        }
        
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
                        headers = resp.headers
                        
                        # Check each security header
                        for header in self.SECURITY_HEADERS:
                            if header in headers:
                                results["headers"][header] = headers[header]
                            else:
                                results["missing_headers"].append(header)
                        
                        # Analyze header values
                        results["vulnerabilities"].extend(
                            self._analyze_header_values(results["headers"])
                        )
                        
                except Exception as e:
                    logger.warning(f"HTTP analysis error: {e}")
                    # Try HTTPS if HTTP failed
                    if "https://" not in base_url:
                        try:
                            https_url = base_url.replace("http://", "https://")
                            async with session.get(https_url, timeout=aiohttp.ClientTimeout(total=8), allow_redirects=True, ssl=False) as resp:
                                headers = resp.headers
                                for header in self.SECURITY_HEADERS:
                                    if header in headers:
                                        results["headers"][header] = headers[header]
                                    else:
                                        results["missing_headers"].append(header)
                                results["vulnerabilities"].extend(
                                    self._analyze_header_values(results["headers"])
                                )
                        except:
                            pass
        
        except Exception as e:
            logger.error(f"HTTP analyzer error: {e}")
            # Return empty results instead of failing
            results["error"] = str(e)
        
        # Always return results, even if empty
        if not results.get("vulnerabilities"):
            # Add at least one finding about missing headers
            if results.get("missing_headers"):
                results["vulnerabilities"].append({
                    "type": "security_headers",
                    "severity": "medium",
                    "issue": f"Missing security headers: {', '.join(results['missing_headers'][:3])}",
                    "recommendation": "Implement missing security headers to improve security posture"
                })
        
        return results
    
    def _analyze_header_values(self, headers: Dict) -> List[Dict]:
        """Analyze header values for misconfigurations"""
        vulnerabilities = []
        
        # Check HSTS
        if "Strict-Transport-Security" in headers:
            hsts = headers["Strict-Transport-Security"]
            if "max-age=0" in hsts or "max-age" not in hsts:
                vulnerabilities.append({
                    "type": "misconfiguration",
                    "severity": "medium",
                    "header": "Strict-Transport-Security",
                    "issue": "HSTS max-age is too low or missing"
                })
        
        # Check X-Frame-Options
        if "X-Frame-Options" in headers:
            xfo = headers["X-Frame-Options"].lower()
            if xfo not in ["deny", "sameorigin"]:
                vulnerabilities.append({
                    "type": "misconfiguration",
                    "severity": "medium",
                    "header": "X-Frame-Options",
                    "issue": "X-Frame-Options should be 'DENY' or 'SAMEORIGIN'"
                })
        
        # Check CSP
        if "Content-Security-Policy" in headers:
            csp = headers["Content-Security-Policy"]
            if "'unsafe-inline'" in csp or "'unsafe-eval'" in csp:
                vulnerabilities.append({
                    "type": "misconfiguration",
                    "severity": "medium",
                    "header": "Content-Security-Policy",
                    "issue": "CSP contains unsafe directives"
                })
        
        return vulnerabilities

