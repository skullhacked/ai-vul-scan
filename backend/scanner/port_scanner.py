"""TCP Port Scanner - Passive connect scanning only"""
import asyncio
import socket
from typing import List, Dict, Optional
import logging

logger = logging.getLogger(__name__)

class PortScanner:
    """Passive TCP port scanner using connect() method"""
    
    COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 1433, 3306, 3389, 5432, 5900, 8080, 8443, 9200]
    
    def __init__(self, target: str, timeout: float = 0.5):
        # Extract hostname from URL
        if "://" in target:
            from urllib.parse import urlparse
            parsed = urlparse(target)
            self.target = parsed.hostname or target.split("://")[-1].split("/")[0].split(":")[0]
        else:
            self.target = target.split("/")[0].split(":")[0]
        self.timeout = timeout
    
    async def scan_port(self, port: int) -> Optional[Dict]:
        """Scan a single port asynchronously"""
        try:
            # Run socket operation in thread pool to avoid blocking
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(None, self._check_port, port)
            
            if result:
                return {
                    "port": port,
                    "state": "open",
                    "service": self._guess_service(port)
                }
        except Exception as e:
            logger.debug(f"Port {port} scan error: {e}")
        
        return None
    
    def _check_port(self, port: int) -> bool:
        """Check if port is open (blocking, runs in executor)"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target, port))
            sock.close()
            return result == 0
        except:
            return False
    
    async def scan_common_ports(self) -> List[Dict]:
        """Scan common ports concurrently with timeout"""
        # Only scan most common ports for speed
        common_web_ports = [80, 443, 8080, 8443, 22, 21, 25, 53]
        tasks = [self.scan_port(port) for port in common_web_ports]
        
        # Use asyncio.wait with timeout
        try:
            done, pending = await asyncio.wait(
                tasks,
                timeout=self.timeout * len(common_web_ports) + 2,
                return_when=asyncio.ALL_COMPLETED
            )
            # Cancel pending tasks
            for task in pending:
                task.cancel()
            
            results = []
            for task in done:
                try:
                    result = await task
                    if result:
                        results.append(result)
                except Exception:
                    pass
            
            return results
        except Exception as e:
            logger.warning(f"Port scan error: {e}")
            return []
    
    def _guess_service(self, port: int) -> str:
        """Guess service based on port number"""
        services = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
            993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 3306: "MySQL",
            3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 8080: "HTTP-Proxy",
            8443: "HTTPS-Alt", 9200: "Elasticsearch"
        }
        return services.get(port, "Unknown")

