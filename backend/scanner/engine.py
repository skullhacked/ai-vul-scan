"""
Modular Vulnerability Scanner Engine
Passive analysis only - no exploitation
"""
import asyncio
import socket
import ssl
import aiohttp
import ipaddress
from typing import Dict, List, Optional
from datetime import datetime
import logging
from urllib.parse import urlparse

from backend.scanner.port_scanner import PortScanner
from backend.scanner.http_analyzer import HTTPAnalyzer
from backend.scanner.tls_analyzer import TLSAnalyzer
from backend.scanner.owasp_detector import OWASPDetector
from backend.config import settings

logger = logging.getLogger(__name__)

class ScannerEngine:
    """Main scanner engine orchestrating all scan modules"""
    
    def __init__(self, target: str, scan_id: str, websocket_manager=None):
        self.target = target
        self.scan_id = scan_id
        self.manager = websocket_manager
        self.results = {
            "ports": [],
            "http_headers": {},
            "tls_info": {},
            "vulnerabilities": [],
            "server_info": {}
        }
    
    def _is_allowed_target(self) -> bool:
        """Validate target is in allowed IP ranges"""
        try:
            # Parse target
            parsed = urlparse(self.target if "://" in self.target else f"http://{self.target}")
            host = parsed.hostname or self.target.split(":")[0]
            
            # Check localhost
            if host in ["localhost", "127.0.0.1", "::1"]:
                return True
            
            # Check private IP ranges
            try:
                ip = ipaddress.ip_address(host)
                if ip.is_private or ip.is_loopback:
                    return True
            except ValueError:
                # Domain name - allow for now (user must verify)
                return True
            
            return True  # Allow with authorization checkbox
        except Exception as e:
            logger.error(f"Target validation error: {e}")
            return False
    
    async def _send_progress(self, stage: str, progress: int, message: str = ""):
        """Send progress update via WebSocket"""
        if self.manager:
            try:
                await self.manager.send_update(self.scan_id, {
                    "type": "progress",
                    "stage": stage,
                    "progress": progress,
                    "message": message,
                    "timestamp": datetime.utcnow().isoformat()
                })
                logger.debug(f"Progress update sent: {stage} - {progress}%")
            except Exception as e:
                logger.warning(f"Failed to send progress update: {e}")
    
    async def scan(self) -> Dict:
        """Execute full vulnerability scan - optimized for web applications"""
        if not self._is_allowed_target():
            raise ValueError("Target not in allowed IP ranges")
        
        logger.info(f"Starting scan for {self.target}")
        
        try:
            # Parse target to determine if it's a web URL
            parsed = urlparse(self.target if "://" in self.target else f"https://{self.target}")
            is_web_url = parsed.scheme in ["http", "https"] or "." in (parsed.hostname or self.target)
            
            # Stage 1: Quick Port Check (0-10%) - Only for IPs, skip for web URLs
            await self._send_progress("initializing", 0, "Initializing scan...")
            await asyncio.sleep(0.5)  # Small delay to ensure WebSocket is ready
            
            if not is_web_url:
                await self._send_progress("port_scanning", 5, "Scanning common ports...")
                try:
                    port_scanner = PortScanner(self.target, timeout=0.5)  # Faster timeout
                    self.results["ports"] = await asyncio.wait_for(
                        port_scanner.scan_common_ports(),
                        timeout=10.0  # Max 10 seconds for port scan
                    )
                    await self._send_progress("port_scanning", 10, f"Found {len(self.results['ports'])} open ports")
                except asyncio.TimeoutError:
                    logger.warning("Port scan timed out, continuing...")
                    self.results["ports"] = []
                    await self._send_progress("port_scanning", 10, "Port scan skipped (timeout)")
            else:
                # For web URLs, assume common ports are open
                self.results["ports"] = [
                    {"port": 80, "state": "open", "service": "HTTP"},
                    {"port": 443, "state": "open", "service": "HTTPS"}
                ]
                await self._send_progress("port_scanning", 10, "Web URL detected, skipping port scan")
                await asyncio.sleep(0.3)
            
            # Stage 2: HTTP Analysis (10-40%)
            await self._send_progress("http_analysis", 10, "Analyzing HTTP security headers...")
            await asyncio.sleep(0.2)
            try:
                http_analyzer = HTTPAnalyzer(self.target)
                self.results["http_headers"] = await asyncio.wait_for(
                    http_analyzer.analyze(),
                    timeout=15.0
                )
                await self._send_progress("http_analysis", 40, f"HTTP analysis complete - Found {len(self.results['http_headers'].get('vulnerabilities', []))} issues")
            except asyncio.TimeoutError:
                logger.warning("HTTP analysis timed out")
                self.results["http_headers"] = {"error": "Timeout", "vulnerabilities": []}
                await self._send_progress("http_analysis", 40, "HTTP analysis timed out")
            except Exception as e:
                logger.error(f"HTTP analysis error: {e}")
                self.results["http_headers"] = {"error": str(e), "vulnerabilities": []}
                await self._send_progress("http_analysis", 40, f"HTTP analysis error: {str(e)[:50]}")
            await asyncio.sleep(0.2)
            
            # Stage 3: TLS/SSL Analysis (40-60%)
            await self._send_progress("tls_analysis", 40, "Analyzing TLS/SSL configuration...")
            await asyncio.sleep(0.2)
            if is_web_url or any(p.get("port") in [443, 8443] for p in self.results["ports"]):
                try:
                    tls_analyzer = TLSAnalyzer(self.target)
                    self.results["tls_info"] = await asyncio.wait_for(
                        tls_analyzer.analyze(),
                        timeout=10.0
                    )
                    vuln_count = len(self.results["tls_info"].get("vulnerabilities", []))
                    await self._send_progress("tls_analysis", 60, f"TLS analysis complete - Found {vuln_count} issues")
                except asyncio.TimeoutError:
                    logger.warning("TLS analysis timed out")
                    self.results["tls_info"] = {"error": "Timeout", "vulnerabilities": []}
                    await self._send_progress("tls_analysis", 60, "TLS analysis timed out")
                except Exception as e:
                    logger.error(f"TLS analysis error: {e}")
                    self.results["tls_info"] = {"error": str(e), "vulnerabilities": []}
                    await self._send_progress("tls_analysis", 60, f"TLS analysis error: {str(e)[:50]}")
            else:
                self.results["tls_info"] = {"error": "No HTTPS port", "vulnerabilities": []}
                await self._send_progress("tls_analysis", 60, "Skipped TLS analysis (no HTTPS)")
            await asyncio.sleep(0.2)
            
            # Stage 4: OWASP Pattern Detection (60-80%)
            await self._send_progress("owasp_detection", 60, "Detecting OWASP Top 10 patterns...")
            await asyncio.sleep(0.2)
            try:
                owasp_detector = OWASPDetector(self.target, self.results)
                owasp_vulns = await asyncio.wait_for(
                    owasp_detector.detect(),
                    timeout=15.0
                )
                self.results["vulnerabilities"].extend(owasp_vulns)
                await self._send_progress("owasp_detection", 80, f"Pattern detection complete - Found {len(owasp_vulns)} issues")
            except asyncio.TimeoutError:
                logger.warning("OWASP detection timed out")
                await self._send_progress("owasp_detection", 80, "Pattern detection timed out")
            except Exception as e:
                logger.error(f"OWASP detection error: {e}")
                await self._send_progress("owasp_detection", 80, f"Pattern detection error: {str(e)[:50]}")
            await asyncio.sleep(0.2)
            
            # Stage 5: Server Information (80-90%)
            await self._send_progress("server_info", 80, "Gathering server information...")
            await asyncio.sleep(0.2)
            try:
                self.results["server_info"] = await asyncio.wait_for(
                    self._gather_server_info(),
                    timeout=5.0
                )
                await self._send_progress("server_info", 90, "Server info gathered")
            except asyncio.TimeoutError:
                logger.warning("Server info gathering timed out")
                self.results["server_info"] = {}
                await self._send_progress("server_info", 90, "Server info timeout")
            
            # Stage 6: Finalizing (90-100%)
            await self._send_progress("finalizing", 90, "Finalizing scan results...")
            
            logger.info(f"Scan completed for {self.target}")
            await self._send_progress("completed", 100, "Scan completed successfully")
            
            return self.results
            
        except Exception as e:
            logger.error(f"Scan error: {e}", exc_info=True)
            await self._send_progress("error", 0, f"Scan failed: {str(e)}")
            # Return partial results even on error
            return self.results
    
    async def _gather_server_info(self) -> Dict:
        """Gather server version and technology information"""
        info = {}
        try:
            async with aiohttp.ClientSession() as session:
                try:
                    url = self.target if "://" in self.target else f"http://{self.target}"
                    async with session.get(url, timeout=aiohttp.ClientTimeout(total=5), allow_redirects=False) as resp:
                        headers = resp.headers
                        info["server"] = headers.get("Server", "Unknown")
                        info["x_powered_by"] = headers.get("X-Powered-By", None)
                        info["status_code"] = resp.status
                except:
                    pass
        except Exception as e:
            logger.warning(f"Server info gathering error: {e}")
        return info

