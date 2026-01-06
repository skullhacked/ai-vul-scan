"""AI-powered vulnerability analysis using local models"""
import httpx
import json
import logging
from typing import Dict, List, Optional
from backend.config import settings

logger = logging.getLogger(__name__)

class AIAnalyzer:
    """Analyze vulnerabilities using local AI models"""
    
    def __init__(self):
        self.provider = settings.AI_PROVIDER
        self.base_url = settings.OLLAMA_BASE_URL
        self.model = settings.OLLAMA_MODEL
        self.enabled = settings.AI_ENABLED
    
    async def analyze_vulnerabilities(self, vulnerabilities: List[Dict], scan_results: Dict) -> List[Dict]:
        """Analyze vulnerabilities and add AI insights"""
        if not self.enabled:
            logger.info("AI analysis disabled")
            return vulnerabilities
        
        try:
            if self.provider == "ollama":
                return await self._analyze_with_ollama(vulnerabilities, scan_results)
            else:
                logger.warning(f"AI provider {self.provider} not yet implemented")
                return vulnerabilities
        except Exception as e:
            logger.error(f"AI analysis error: {e}")
            return vulnerabilities
    
    async def _analyze_with_ollama(self, vulnerabilities: List[Dict], scan_results: Dict) -> List[Dict]:
        """Analyze using Ollama with fallback to rule-based analysis"""
        enhanced_vulns = []
        
        for vuln in vulnerabilities:
            try:
                prompt = self._create_analysis_prompt(vuln, scan_results)
                analysis = await self._query_ollama(prompt)
                
                # Check if Ollama actually worked
                if analysis and "unavailable" not in analysis.lower():
                    vuln["ai_analysis"] = analysis
                    vuln["ai_severity"] = self._extract_severity(analysis)
                    vuln["ai_recommendation"] = self._extract_recommendation(analysis)
                else:
                    # Fallback to rule-based analysis
                    vuln["ai_analysis"] = self._rule_based_analysis(vuln, scan_results)
                    vuln["ai_severity"] = vuln.get("severity", "medium")
                    vuln["ai_recommendation"] = vuln.get("recommendation", "Review and remediate based on security best practices.")
                
            except Exception as e:
                logger.warning(f"Failed to analyze vulnerability with AI: {e}")
                # Use rule-based analysis as fallback
                vuln["ai_analysis"] = self._rule_based_analysis(vuln, scan_results)
                vuln["ai_severity"] = vuln.get("severity", "medium")
                vuln["ai_recommendation"] = vuln.get("recommendation", "Review and remediate based on security best practices.")
            
            enhanced_vulns.append(vuln)
        
        return enhanced_vulns
    
    def _rule_based_analysis(self, vuln: Dict, scan_results: Dict) -> str:
        """Rule-based AI analysis fallback - provides intelligent analysis without Ollama"""
        vuln_type = vuln.get("type", "").lower()
        severity = vuln.get("severity", "medium").lower()
        issue = vuln.get("issue", "")
        owasp = vuln.get("owasp", "")
        
        # Build intelligent analysis based on vulnerability type
        analysis_parts = []
        
        # Severity-based impact assessment
        if severity == "critical":
            analysis_parts.append("This is a critical security issue that requires immediate attention.")
            impact = "could lead to complete system compromise, data breach, or service disruption."
        elif severity == "high":
            analysis_parts.append("This is a high-severity vulnerability that poses significant risk.")
            impact = "could result in unauthorized access, data exposure, or system manipulation."
        elif severity == "medium":
            analysis_parts.append("This is a medium-severity issue that should be addressed promptly.")
            impact = "could potentially be exploited to gain limited access or expose sensitive information."
        else:
            analysis_parts.append("This is a lower-severity finding that should be reviewed.")
            impact = "may indicate security misconfigurations or areas for improvement."
        
        # Type-specific analysis
        if "header" in vuln_type or "security_headers" in vuln_type:
            analysis_parts.append(f"Missing or misconfigured security headers {impact}")
            analysis_parts.append("Security headers are the first line of defense against common web attacks like XSS, clickjacking, and MIME-sniffing.")
        elif "tls" in vuln_type or "ssl" in vuln_type or "certificate" in vuln_type:
            analysis_parts.append(f"TLS/SSL configuration issues {impact}")
            analysis_parts.append("Weak encryption or certificate problems can allow attackers to intercept or manipulate communications.")
        elif "injection" in vuln_type:
            analysis_parts.append(f"Injection vulnerabilities {impact}")
            analysis_parts.append("These can allow attackers to execute malicious code or access unauthorized data.")
        elif "xss" in vuln_type:
            analysis_parts.append(f"Cross-site scripting (XSS) vulnerabilities {impact}")
            analysis_parts.append("XSS can be used to steal user sessions, deface websites, or redirect users to malicious sites.")
        elif "access" in vuln_type or "authentication" in vuln_type:
            analysis_parts.append(f"Access control or authentication issues {impact}")
            analysis_parts.append("These vulnerabilities can allow unauthorized users to access restricted resources or perform privileged actions.")
        elif "misconfiguration" in vuln_type:
            analysis_parts.append(f"Security misconfiguration {impact}")
            analysis_parts.append("Misconfigurations often expose sensitive information or create attack surfaces.")
        else:
            analysis_parts.append(f"This vulnerability {impact}")
        
        # OWASP context
        if owasp:
            analysis_parts.append(f"This relates to OWASP Top 10 category {owasp}, which is a recognized security risk pattern.")
        
        # Recommendation context
        if vuln.get("recommendation"):
            analysis_parts.append("Follow the provided recommendations to remediate this issue.")
        
        return " ".join(analysis_parts)
    
    def _create_analysis_prompt(self, vuln: Dict, scan_results: Dict) -> str:
        """Create prompt for AI analysis"""
        return f"""You are a cybersecurity expert analyzing a vulnerability scan result.

Vulnerability Details:
- Type: {vuln.get('type', 'Unknown')}
- Severity: {vuln.get('severity', 'Unknown')}
- Issue: {vuln.get('issue', 'N/A')}
- OWASP Category: {vuln.get('owasp', 'N/A')}

Target Information:
- Ports Open: {len(scan_results.get('ports', []))}
- TLS Version: {scan_results.get('tls_info', {}).get('version', 'N/A')}

Provide a brief analysis (2-3 sentences) explaining:
1. Why this vulnerability matters
2. Potential impact
3. Recommended remediation steps

Keep the response concise and technical but accessible."""
    
    async def _query_ollama(self, prompt: str) -> str:
        """Query Ollama API"""
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(
                    f"{self.base_url}/api/generate",
                    json={
                        "model": self.model,
                        "prompt": prompt,
                        "stream": False
                    }
                )
                if response.status_code == 200:
                    result = response.json()
                    return result.get("response", "Analysis unavailable")
                else:
                    logger.error(f"Ollama API error: {response.status_code}")
                    return "AI analysis unavailable"
        except Exception as e:
            logger.error(f"Ollama connection error: {e}")
            return "AI analysis unavailable - ensure Ollama is running"
    
    def _extract_severity(self, analysis: str) -> str:
        """Extract severity from AI analysis"""
        analysis_lower = analysis.lower()
        if any(word in analysis_lower for word in ["critical", "severe", "immediate"]):
            return "critical"
        elif any(word in analysis_lower for word in ["high", "serious", "important"]):
            return "high"
        elif any(word in analysis_lower for word in ["medium", "moderate"]):
            return "medium"
        else:
            return "low"
    
    def _extract_recommendation(self, analysis: str) -> str:
        """Extract recommendation from AI analysis"""
        # Simple extraction - look for sentences with "recommend", "should", "must"
        sentences = analysis.split(".")
        recommendations = [s.strip() for s in sentences if any(word in s.lower() for word in ["recommend", "should", "must", "implement", "enable"])]
        return ". ".join(recommendations[:2]) if recommendations else "Review and remediate based on security best practices."
    
    async def generate_summary(self, scan_results: Dict, vulnerabilities: List[Dict]) -> Dict:
        """Generate executive and technical summaries"""
        if not self.enabled:
            return {
                "executive": "Scan completed. Review results for vulnerabilities.",
                "technical": "See detailed vulnerability list for technical information."
            }
        
        try:
            prompt = f"""Generate two summaries for a vulnerability scan:

Scan Results:
- Target: {scan_results.get('target', 'Unknown')}
- Open Ports: {len(scan_results.get('ports', []))}
- Total Vulnerabilities: {len(vulnerabilities)}
- Severity Breakdown: {self._count_severities(vulnerabilities)}

Provide:
1. Executive Summary (1-2 sentences for management)
2. Technical Summary (2-3 sentences for security team)

Format as JSON:
{{"executive": "...", "technical": "..."}}"""
            
            response = await self._query_ollama(prompt)
            
            # Try to parse JSON response
            try:
                return json.loads(response)
            except:
                # Fallback if not JSON
                return {
                    "executive": response[:200] + "..." if len(response) > 200 else response,
                    "technical": response
                }
        
        except Exception as e:
            logger.error(f"Summary generation error: {e}")
            return {
                "executive": "Scan completed successfully.",
                "technical": "Review individual vulnerabilities for details."
            }
    
    def _count_severities(self, vulnerabilities: List[Dict]) -> Dict:
        """Count vulnerabilities by severity"""
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "info").lower()
            counts[severity] = counts.get(severity, 0) + 1
        return counts

