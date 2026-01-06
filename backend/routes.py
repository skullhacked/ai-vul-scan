"""API Routes"""
from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field
from typing import List, Optional, Dict
import uuid
from datetime import datetime
import logging

import asyncio
from backend.scanner.engine import ScannerEngine
from backend.ai.analyzer import AIAnalyzer
from backend.database import Scan, Vulnerability, async_session_maker, User
from backend.websocket_manager import ConnectionManager
from backend.reports import generate_html_report
from backend.config import settings
from backend.auth import get_current_active_user
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi.responses import FileResponse
from fastapi import Depends

logger = logging.getLogger(__name__)

router = APIRouter()
manager = ConnectionManager()

# Request/Response models
class ScanRequest(BaseModel):
    target: str = Field(..., description="Target to scan (IP, domain, or URL)")
    authorized: bool = Field(..., description="Authorization confirmation")

class ScanResponse(BaseModel):
    scan_id: str
    status: str
    message: str

class VulnerabilityResponse(BaseModel):
    id: str
    title: str
    description: Optional[str]
    severity: str
    category: str
    recommendation: Optional[str]
    ai_analysis: Optional[str]

class ScanStatusResponse(BaseModel):
    scan_id: str
    status: str
    progress: int
    risk_score: float
    total_vulnerabilities: int

@router.post("/api/scan/start", response_model=ScanResponse)
async def start_scan(
    request: ScanRequest, 
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_active_user)
):
    """Start a new vulnerability scan"""
    if not request.authorized:
        raise HTTPException(status_code=400, detail="Authorization required")
    
    scan_id = str(uuid.uuid4())
    
    # Create scan record
    async with async_session_maker() as session:
        scan = Scan(
            id=scan_id,
            target=request.target,
            status="pending",
            authorized=request.authorized
        )
        session.add(scan)
        await session.commit()
    
    # Start background scan
    background_tasks.add_task(run_scan, scan_id, request.target)
    
    return ScanResponse(
        scan_id=scan_id,
        status="pending",
        message="Scan started successfully"
    )

async def run_scan(scan_id: str, target: str):
    """Background task to run the scan"""
    async with async_session_maker() as session:
        try:
            # Update status to running
            result = await session.execute(select(Scan).where(Scan.id == scan_id))
            scan = result.scalar_one()
            scan.status = "running"
            await session.commit()
            
            # Send initial progress
            await manager.send_update(scan_id, {
                "type": "progress",
                "stage": "initializing",
                "progress": 0,
                "message": "Starting vulnerability scan..."
            })
            
            # Run scanner with overall timeout
            scanner = ScannerEngine(target, scan_id, manager)
            try:
                scan_results = await asyncio.wait_for(
                    scanner.scan(),
                    timeout=settings.SCAN_TIMEOUT
                )
            except asyncio.TimeoutError:
                logger.error(f"Scan timed out after {settings.SCAN_TIMEOUT} seconds")
                await manager.send_update(scan_id, {
                    "type": "error",
                    "message": f"Scan timed out after {settings.SCAN_TIMEOUT} seconds"
                })
                raise ValueError(f"Scan timed out after {settings.SCAN_TIMEOUT} seconds")
            
            # Collect all vulnerabilities
            all_vulnerabilities = []
            
            # From HTTP analyzer
            if "vulnerabilities" in scan_results.get("http_headers", {}):
                all_vulnerabilities.extend(scan_results["http_headers"]["vulnerabilities"])
            
            # From TLS analyzer
            if "vulnerabilities" in scan_results.get("tls_info", {}):
                all_vulnerabilities.extend(scan_results["tls_info"]["vulnerabilities"])
            
            # From OWASP detector
            all_vulnerabilities.extend(scan_results.get("vulnerabilities", []))
            
            # AI Analysis (if enabled)
            enhanced_vulnerabilities = all_vulnerabilities
            if settings.AI_ENABLED:
                try:
                    await manager.send_update(scan_id, {
                        "type": "progress",
                        "stage": "ai_analysis",
                        "progress": 85,
                        "message": "AI analyzing vulnerabilities..."
                    })
                    ai_analyzer = AIAnalyzer()
                    enhanced_vulnerabilities = await ai_analyzer.analyze_vulnerabilities(
                        all_vulnerabilities,
                        scan_results
                    )
                    await manager.send_update(scan_id, {
                        "type": "progress",
                        "stage": "ai_analysis",
                        "progress": 95,
                        "message": "AI analysis complete"
                    })
                except Exception as e:
                    logger.warning(f"AI analysis failed: {e}, using basic results")
                    # Continue without AI enhancement
            
            # Calculate risk score
            risk_score = calculate_risk_score(enhanced_vulnerabilities)
            
            # Ensure we have at least some results
            if not enhanced_vulnerabilities:
                # Add a default "scan complete" message
                enhanced_vulnerabilities = [{
                    "type": "info",
                    "severity": "info",
                    "issue": "Scan completed successfully. No critical vulnerabilities detected.",
                    "recommendation": "Continue regular security assessments."
                }]
            
            # Save vulnerabilities
            for vuln in enhanced_vulnerabilities:
                vuln_id = str(uuid.uuid4())
                vulnerability = Vulnerability(
                    id=vuln_id,
                    scan_id=scan_id,
                    title=vuln.get("issue", "Vulnerability"),
                    description=vuln.get("issue", ""),
                    severity=vuln.get("severity", "info"),
                    category=vuln.get("type", "unknown"),
                    evidence=vuln,
                    recommendation=vuln.get("recommendation") or vuln.get("ai_recommendation", ""),
                    owasp_category=vuln.get("owasp"),
                    ai_analysis=vuln.get("ai_analysis")
                )
                session.add(vulnerability)
            
            # Update scan
            scan.status = "completed"
            scan.completed_at = datetime.utcnow()
            scan.risk_score = risk_score
            scan.total_vulnerabilities = len(enhanced_vulnerabilities)
            await session.commit()
            
            # Send completion notification
            await manager.send_update(scan_id, {
                "type": "completed",
                "scan_id": scan_id,
                "risk_score": risk_score,
                "total_vulnerabilities": len(enhanced_vulnerabilities)
            })
            
        except Exception as e:
            logger.error(f"Scan error: {e}")
            async with async_session_maker() as session:
                result = await session.execute(select(Scan).where(Scan.id == scan_id))
                scan = result.scalar_one()
                scan.status = "failed"
                await session.commit()
            
            await manager.send_update(scan_id, {
                "type": "error",
                "message": str(e)
            })

def calculate_risk_score(vulnerabilities: List[Dict]) -> float:
    """Calculate overall risk score"""
    weights = {"critical": 10, "high": 7, "medium": 4, "low": 2, "info": 1}
    total_score = sum(weights.get(v.get("severity", "info").lower(), 1) for v in vulnerabilities)
    # Normalize to 0-100
    return min(100, total_score * 2)

@router.get("/api/scan/{scan_id}/status", response_model=ScanStatusResponse)
async def get_scan_status(scan_id: str):
    """Get scan status"""
    async with async_session_maker() as session:
        result = await session.execute(select(Scan).where(Scan.id == scan_id))
        scan = result.scalar_one_or_none()
        
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        return ScanStatusResponse(
            scan_id=scan.id,
            status=scan.status,
            progress=100 if scan.status == "completed" else 50 if scan.status == "running" else 0,
            risk_score=scan.risk_score,
            total_vulnerabilities=scan.total_vulnerabilities
        )

@router.get("/api/scan/{scan_id}/vulnerabilities", response_model=List[VulnerabilityResponse])
async def get_vulnerabilities(scan_id: str):
    """Get vulnerabilities for a scan"""
    async with async_session_maker() as session:
        result = await session.execute(
            select(Vulnerability).where(Vulnerability.scan_id == scan_id)
        )
        vulnerabilities = result.scalars().all()
        
        return [
            VulnerabilityResponse(
                id=v.id,
                title=v.title,
                description=v.description,
                severity=v.severity,
                category=v.category,
                recommendation=v.recommendation,
                ai_analysis=v.ai_analysis
            )
            for v in vulnerabilities
        ]

@router.get("/api/scans")
async def list_scans():
    """List all scans"""
    async with async_session_maker() as session:
        result = await session.execute(select(Scan).order_by(Scan.created_at.desc()).limit(50))
        scans = result.scalars().all()
        
        return [
            {
                "id": s.id,
                "target": s.target,
                "status": s.status,
                "risk_score": s.risk_score,
                "total_vulnerabilities": s.total_vulnerabilities,
                "created_at": s.created_at.isoformat() if s.created_at else None
            }
            for s in scans
        ]

@router.get("/api/scan/{scan_id}/report")
async def get_report(
    scan_id: str,
    current_user: User = Depends(get_current_active_user)
):
    """Generate and download HTML report"""
    async with async_session_maker() as session:
        # Get scan
        result = await session.execute(select(Scan).where(Scan.id == scan_id))
        scan = result.scalar_one_or_none()
        
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        # Get vulnerabilities
        vuln_result = await session.execute(
            select(Vulnerability).where(Vulnerability.scan_id == scan_id)
        )
        vulnerabilities = vuln_result.scalars().all()
        
        # Convert to dict
        vuln_dicts = [
            {
                "title": v.title,
                "description": v.description,
                "severity": v.severity,
                "category": v.category,
                "recommendation": v.recommendation,
                "ai_analysis": v.ai_analysis
            }
            for v in vulnerabilities
        ]
        
        # Generate report
        try:
            report_path = await generate_html_report(
                scan_id,
                scan.target,
                vuln_dicts,
                scan.risk_score or 0.0
            )
            
            return FileResponse(
                report_path,
                media_type="text/html",
                filename=f"vulnerability_report_{scan_id}.html",
                headers={
                    "Content-Disposition": f"attachment; filename=vulnerability_report_{scan_id}.html"
                }
            )
        except Exception as e:
            logger.error(f"Report generation error: {e}")
            raise HTTPException(status_code=500, detail=f"Failed to generate report: {str(e)}")

