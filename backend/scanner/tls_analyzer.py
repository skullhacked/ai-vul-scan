"""TLS/SSL Configuration Analyzer"""
import ssl
import socket
import asyncio
from typing import Dict, List
import logging
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

class TLSAnalyzer:
    """Analyze TLS/SSL configuration and certificates"""
    
    def __init__(self, target: str):
        self.target = target
    
    async def analyze(self) -> Dict:
        """Analyze TLS/SSL configuration with timeout"""
        results = {
            "version": None,
            "cipher": None,
            "certificate": {},
            "vulnerabilities": []
        }
        
        try:
            # Normalize target
            if "://" not in self.target:
                target_url = f"https://{self.target}"
            else:
                target_url = self.target
            
            parsed = urlparse(target_url)
            hostname = parsed.hostname or self.target.split(":")[0]
            port = parsed.port or 443
            
            # Run TLS check in executor with timeout
            loop = asyncio.get_event_loop()
            tls_data = await asyncio.wait_for(
                loop.run_in_executor(None, self._check_tls, hostname, port),
                timeout=8.0
            )
            
            if tls_data:
                results.update(tls_data)
        
        except asyncio.TimeoutError:
            logger.warning("TLS analysis timed out")
            results["error"] = "Timeout"
        except Exception as e:
            logger.warning(f"TLS analysis error: {e}")
            results["error"] = str(e)
        
        return results
    
    def _check_tls(self, hostname: str, port: int) -> Dict:
        """Check TLS configuration (blocking, runs in executor)"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False  # Faster, less secure but acceptable for scanning
            context.verify_mode = ssl.CERT_NONE  # Faster scanning
            
            with socket.create_connection((hostname, port), timeout=3) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    version = ssock.version()
                    cipher = ssock.cipher()
                    cert = ssock.getpeercert()
                    
                    result = {
                        "version": version,
                        "cipher": None,
                        "certificate": {},
                        "vulnerabilities": []
                    }
                    
                    if cipher:
                        result["cipher"] = {
                            "name": cipher[0],
                            "version": cipher[1],
                            "bits": cipher[2]
                        }
                    
                    if cert:
                        result["certificate"] = {
                            "subject": dict(x[0] for x in cert.get("subject", [])),
                            "issuer": dict(x[0] for x in cert.get("issuer", [])),
                            "version": cert.get("version"),
                            "notBefore": cert.get("notBefore"),
                            "notAfter": cert.get("notAfter")
                        }
                    
                    result["vulnerabilities"] = self._analyze_tls_config(version, cipher, cert)
                    return result
        except Exception as e:
            logger.debug(f"TLS check failed: {e}")
            return None
    
    def _analyze_tls_config(self, version: str, cipher: tuple, cert: dict) -> List[Dict]:
        """Analyze TLS configuration for vulnerabilities"""
        vulnerabilities = []
        
        # Check TLS version
        if version in ["TLSv1", "TLSv1.1", "SSLv2", "SSLv3"]:
            vulnerabilities.append({
                "type": "weak_protocol",
                "severity": "high",
                "issue": f"Outdated TLS version: {version}",
                "recommendation": "Upgrade to TLS 1.2 or higher"
            })
        
        # Check cipher strength
        if cipher:
            bits = cipher[2]
            if bits < 128:
                vulnerabilities.append({
                    "type": "weak_cipher",
                    "severity": "high",
                    "issue": f"Weak cipher key length: {bits} bits",
                    "recommendation": "Use ciphers with at least 128-bit keys"
                })
        
        # Check certificate expiration
        if cert and "notAfter" in cert:
            from datetime import datetime
            try:
                not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                days_until_expiry = (not_after - datetime.utcnow()).days
                if days_until_expiry < 30:
                    vulnerabilities.append({
                        "type": "certificate_expiring",
                        "severity": "medium" if days_until_expiry > 0 else "high",
                        "issue": f"Certificate expires in {days_until_expiry} days",
                        "recommendation": "Renew certificate before expiration"
                    })
            except:
                pass
        
        return vulnerabilities
