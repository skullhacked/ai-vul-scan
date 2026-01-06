"""Report Generation Module"""
from jinja2 import Template
from typing import Dict, List
from datetime import datetime
import aiofiles
import os
from pathlib import Path

REPORT_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vulnerability Scan Report - {{ scan_id }}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Courier New', monospace;
            background: #0a0e27;
            color: #e0e6ed;
            padding: 2rem;
            line-height: 1.6;
        }
        .header {
            border-bottom: 2px solid rgba(0, 255, 255, 0.3);
            padding-bottom: 2rem;
            margin-bottom: 2rem;
        }
        .header h1 {
            color: #00ffff;
            font-size: 2rem;
            letter-spacing: 0.2em;
            text-transform: uppercase;
        }
        .meta {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-top: 1rem;
        }
        .meta-item {
            padding: 1rem;
            background: rgba(0, 255, 255, 0.05);
            border: 1px solid rgba(0, 255, 255, 0.2);
            border-radius: 4px;
        }
        .meta-label {
            font-size: 0.8rem;
            color: #8b9dc3;
            text-transform: uppercase;
            margin-bottom: 0.5rem;
        }
        .meta-value {
            font-size: 1.2rem;
            color: #00ffff;
            font-weight: bold;
        }
        .risk-score {
            text-align: center;
            padding: 2rem;
            margin: 2rem 0;
            background: rgba(0, 0, 0, 0.3);
            border: 2px solid rgba(0, 255, 255, 0.3);
            border-radius: 8px;
        }
        .risk-value {
            font-size: 4rem;
            font-weight: bold;
            background: linear-gradient(90deg, #00ffff, #9d4edd);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }
        .vulnerabilities {
            margin-top: 2rem;
        }
        .vuln-card {
            padding: 1.5rem;
            margin-bottom: 1rem;
            background: rgba(0, 0, 0, 0.3);
            border-left: 4px solid;
            border-radius: 4px;
        }
        .vuln-card.critical { border-left-color: #ff006e; }
        .vuln-card.high { border-left-color: #ffbe0b; }
        .vuln-card.medium { border-left-color: #00ffff; }
        .vuln-card.low { border-left-color: #00ff88; }
        .vuln-header {
            display: flex;
            justify-content: space-between;
            align-items: start;
            margin-bottom: 1rem;
        }
        .vuln-title {
            font-size: 1.2rem;
            font-weight: bold;
        }
        .vuln-severity {
            padding: 0.5rem 1rem;
            border-radius: 4px;
            font-weight: bold;
            text-transform: uppercase;
        }
        .vuln-severity.critical {
            background: rgba(255, 0, 110, 0.2);
            color: #ff006e;
        }
        .vuln-severity.high {
            background: rgba(255, 190, 11, 0.2);
            color: #ffbe0b;
        }
        .vuln-severity.medium {
            background: rgba(0, 255, 255, 0.2);
            color: #00ffff;
        }
        .vuln-severity.low {
            background: rgba(0, 255, 136, 0.2);
            color: #00ff88;
        }
        .vuln-section {
            margin-top: 1rem;
            padding: 1rem;
            background: rgba(0, 255, 255, 0.05);
            border-left: 3px solid #00ffff;
            border-radius: 4px;
        }
        .vuln-section strong {
            color: #00ffff;
            display: block;
            margin-bottom: 0.5rem;
        }
        .footer {
            margin-top: 3rem;
            padding-top: 2rem;
            border-top: 1px solid rgba(0, 255, 255, 0.3);
            text-align: center;
            color: #8b9dc3;
            font-size: 0.9rem;
        }
        @media print {
            body { background: white; color: black; }
            .vuln-card { break-inside: avoid; }
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>Vulnerability Scan Report</h1>
        <div class="meta">
            <div class="meta-item">
                <div class="meta-label">Target</div>
                <div class="meta-value">{{ target }}</div>
            </div>
            <div class="meta-item">
                <div class="meta-label">Scan ID</div>
                <div class="meta-value">{{ scan_id }}</div>
            </div>
            <div class="meta-item">
                <div class="meta-label">Date</div>
                <div class="meta-value">{{ scan_date }}</div>
            </div>
            <div class="meta-item">
                <div class="meta-label">Total Vulnerabilities</div>
                <div class="meta-value">{{ total_vulns }}</div>
            </div>
        </div>
    </div>

    <div class="risk-score">
        <div style="font-size: 1rem; color: #8b9dc3; margin-bottom: 0.5rem;">RISK SCORE</div>
        <div class="risk-value">{{ risk_score }}</div>
    </div>

    <div class="vulnerabilities">
        <h2 style="color: #00ffff; margin-bottom: 1rem; text-transform: uppercase; letter-spacing: 0.1em;">Vulnerabilities</h2>
        {% for vuln in vulnerabilities %}
        <div class="vuln-card {{ vuln.severity.lower() }}">
            <div class="vuln-header">
                <div class="vuln-title">{{ vuln.title }}</div>
                <div class="vuln-severity {{ vuln.severity.lower() }}">{{ vuln.severity.upper() }}</div>
            </div>
            {% if vuln.description %}
            <div style="margin: 1rem 0; color: #8b9dc3;">{{ vuln.description }}</div>
            {% endif %}
            {% if vuln.category %}
            <div style="margin: 0.5rem 0;"><strong>Category:</strong> {{ vuln.category }}</div>
            {% endif %}
            {% if vuln.recommendation %}
            <div class="vuln-section">
                <strong>Recommendation:</strong>
                {{ vuln.recommendation }}
            </div>
            {% endif %}
            {% if vuln.ai_analysis %}
            <div class="vuln-section" style="border-left-color: #9d4edd; background: rgba(157, 78, 221, 0.05);">
                <strong>AI Analysis:</strong>
                {{ vuln.ai_analysis }}
            </div>
            {% endif %}
        </div>
        {% endfor %}
    </div>

    <div class="footer">
        <p>Generated by AI Vulnerability Scanner</p>
        <p>This report is for authorized defensive security testing only.</p>
    </div>
</body>
</html>
"""

async def generate_html_report(scan_id: str, target: str, vulnerabilities: List[Dict], risk_score: float) -> str:
    """Generate HTML report"""
    try:
        template = Template(REPORT_TEMPLATE)
        
        # Ensure vulnerabilities is a list
        if not isinstance(vulnerabilities, list):
            vulnerabilities = []
        
        html = template.render(
            scan_id=scan_id,
            target=target,
            scan_date=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
            total_vulns=len(vulnerabilities),
            risk_score=round(risk_score) if risk_score else 0,
            vulnerabilities=vulnerabilities
        )
        
        # Save report
        reports_dir = Path("reports")
        reports_dir.mkdir(exist_ok=True)
        
        report_path = reports_dir / f"scan_{scan_id}.html"
        async with aiofiles.open(report_path, 'w', encoding='utf-8') as f:
            await f.write(html)
        
        return str(report_path)
    except Exception as e:
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"Report generation error: {e}", exc_info=True)
        raise

