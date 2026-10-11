import asyncio
import time
import uuid
from datetime import datetime, timezone
from typing import Literal
from fastapi import APIRouter, BackgroundTasks, HTTPException, Query, status
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from core.logger import app_logger
from models.proxy import ProxyRecord
from models.telemetry import ProxyAuditVerdict, ProxyQualityTier
from profiler.engine import ProfilerEngine
from profiler.subnet_analyzer import SubnetAnalyzer
from scoring.quality_engine import QualityScoringEngine
from storage.db import db_manager
from storage.models import AuditSessionModel, ProxyMetricModel
from storage.redis_queue import redis_manager
from api.websocket import ws_manager

router: APIRouter = APIRouter(prefix="/api/v1", tags=["Profiler Operations"])


class ScanSubmissionRequest(BaseModel):
    proxies: list[str] = Field(min_length=1)
    claimed_type: str = Field(default="Residential")


class ScanSubmissionResponse(BaseModel):
    session_id: str
    status: str
    total_proxies: int
    created_at: str


class HealthStatusResponse(BaseModel):
    service_name: str
    status: str
    database_online: bool
    redis_online: bool
    timestamp: str


async def run_background_pool_audit(
    session_id: str,
    raw_proxies: list[str],
    claimed_type: str
) -> None:
    parsed_records: list[ProxyRecord] = []
    for line in raw_proxies:
        cleaned: str = line.strip()
        if not cleaned:
            continue
        try:
            parsed_records.append(ProxyRecord.parse_raw_line(cleaned))
        except Exception:
            pass

    subnet_map = SubnetAnalyzer.analyze_pool_subnets(parsed_records)
    engine: ProfilerEngine = ProfilerEngine()

    total: int = len(parsed_records)
    processed_count: int = 0
    alive_count: int = 0
    ashburn_count: int = 0
    god_tier_count: int = 0
    verdicts: list[ProxyAuditVerdict] = []

    for record in parsed_records:
        verdict: ProxyAuditVerdict = await engine.profile_single_proxy(
            proxy=record,
            subnet_profile=subnet_map.get(record.host),
            claimed_type=claimed_type
        )
        score, tier = QualityScoringEngine.evaluate(
            is_alive=verdict.is_alive,
            latency=verdict.latency,
            edge_pop=verdict.edge_pop,
            asn=verdict.asn,
            subnet=verdict.subnet
        )
        verdict.quality_score = score
        verdict.tier = tier
        verdicts.append(verdict)

        processed_count += 1
        if verdict.is_alive:
            alive_count += 1
        if verdict.edge_pop and verdict.edge_pop.is_ashburn_route:
            ashburn_count += 1
        if verdict.tier == ProxyQualityTier.GOD_TIER_ASHBURN:
            god_tier_count += 1

        await ws_manager.broadcast_progress(
            session_id,
            {
                "session_id": session_id,
                "progress_percentage": round((processed_count / total) * 100.0, 1),
                "processed": processed_count,
                "total": total,
                "alive": alive_count,
                "ashburn_routes": ashburn_count,
                "god_tier": god_tier_count,
                "latest_proxy": verdict.proxy.export_format,
                "latest_status": "ALIVE" if verdict.is_alive else "DEAD",
                "latest_tier": verdict.tier.value
            }
        )

    try:
        async with db_manager.session_factory() as db_session:
            query = select(AuditSessionModel).where(AuditSessionModel.id == session_id)
            result = await db_session.execute(query)
            session_record = result.scalar_one_or_none()

            if session_record:
                session_record.completed_at = datetime.now(timezone.utc)
                session_record.alive_proxies = alive_count
                session_record.ashburn_routes = ashburn_count
                session_record.god_tier_count = god_tier_count
                session_record.status = "COMPLETED"

                for item in verdicts:
                    metric = ProxyMetricModel(
                        session_id=session_id,
                        proxy_endpoint=item.proxy.export_format,
                        is_alive=item.is_alive,
                        error_reason=item.error_reason,
                        colo_code=item.edge_pop.colo_code if item.edge_pop else None,
                        colo_city=item.edge_pop.colo_city if item.edge_pop else None,
                        is_ashburn_route=item.edge_pop.is_ashburn_route if item.edge_pop else False,
                        dns_ms=item.latency.dns_resolution_ms,
                        tcp_ms=item.latency.tcp_handshake_ms,
                        tls_ms=item.latency.tls_handshake_ms,
                        ttfb_ms=item.latency.ttfb_ms,
                        total_rtt_ms=item.latency.total_rtt_ms,
                        asn_number=item.asn.asn_number,
                        asn_org=item.asn.as_organization,
                        actual_type=item.asn.actual_type,
                        is_spoofed_residential=item.asn.is_spoofed_residential,
                        cidr_24=item.subnet.cidr_24 if item.subnet else None,
                        pool_concentration_percentage=item.subnet.pool_concentration_percentage if item.subnet else 0.0,
                        cascade_ban_risk_warning=item.subnet.cascade_ban_risk_warning if item.subnet else False,
                        quality_score=item.quality_score,
                        tier=item.tier.value
                    )
                    db_session.add(metric)

                await db_session.commit()
    except Exception as error:
        app_logger.error(f"Failed to persist audit session metrics: {error}")


@router.get("/health", response_model=HealthStatusResponse)
async def health_check_endpoint() -> HealthStatusResponse:
    pg_status: bool = await db_manager.check_connection()
    redis_status: bool = await redis_manager.check_connection()
    overall: str = "HEALTHY" if pg_status and redis_status else "DEGRADED"

    return HealthStatusResponse(
        service_name="Proxy-Edge-Profiler",
        status=overall,
        database_online=pg_status,
        redis_online=redis_status,
        timestamp=datetime.now(timezone.utc).isoformat()
    )


@router.post("/scan", response_model=ScanSubmissionResponse, status_code=status.HTTP_202_ACCEPTED)
async def submit_scan_session(
    request: ScanSubmissionRequest,
    background_tasks: BackgroundTasks
) -> ScanSubmissionResponse:
    session_id: str = str(uuid.uuid4())
    total_items: int = len(request.proxies)

    try:
        async with db_manager.session_factory() as db_session:
            session_record = AuditSessionModel(
                id=session_id,
                total_proxies=total_items,
                status="IN_PROGRESS"
            )
            db_session.add(session_record)
            await db_session.commit()
    except Exception as error:
        app_logger.warning(f"Could not persist initial session (running headless): {error}")

    background_tasks.add_task(
        run_background_pool_audit,
        session_id=session_id,
        raw_proxies=request.proxies,
        claimed_type=request.claimed_type
    )

    return ScanSubmissionResponse(
        session_id=session_id,
        status="IN_PROGRESS",
        total_proxies=total_items,
        created_at=datetime.now(timezone.utc).isoformat()
    )


@router.get("/report/{session_id}")
async def get_session_report(session_id: str) -> dict:
    async with db_manager.session_factory() as db_session:
        query = select(AuditSessionModel).where(AuditSessionModel.id == session_id)
        result = await db_session.execute(query)
        session_record = result.scalar_one_or_none()

        if not session_record:
            raise HTTPException(status_code=404, detail="Audit session not found")

        metrics_query = select(ProxyMetricModel).where(ProxyMetricModel.session_id == session_id)
        metrics_result = await db_session.execute(metrics_query)
        metrics_records = metrics_result.scalars().all()

        return {
            "session_id": session_record.id,
            "status": session_record.status,
            "started_at": session_record.started_at.isoformat(),
            "completed_at": session_record.completed_at.isoformat() if session_record.completed_at else None,
            "summary": {
                "total": session_record.total_proxies,
                "alive": session_record.alive_proxies,
                "ashburn_routes": session_record.ashburn_routes,
                "god_tier_count": session_record.god_tier_count
            },
            "metrics": [
                {
                    "endpoint": m.proxy_endpoint,
                    "is_alive": m.is_alive,
                    "colo": m.colo_code,
                    "is_ashburn": m.is_ashburn_route,
                    "total_rtt_ms": m.total_rtt_ms,
                    "asn_org": m.asn_org,
                    "quality_score": m.quality_score,
                    "tier": m.tier
                }
                for m in metrics_records
            ]
        }


@router.get("/export/{session_id}/{tier_type}", response_class=PlainTextResponse)
async def export_session_tier_file(
    session_id: str,
    tier_type: Literal["god_tier_ashburn", "clean_residential", "discarded"]
) -> PlainTextResponse:
    tier_mapping: dict[str, str] = {
        "god_tier_ashburn": ProxyQualityTier.GOD_TIER_ASHBURN.value,
        "clean_residential": ProxyQualityTier.CLEAN_RESIDENTIAL.value,
        "discarded": ProxyQualityTier.DISCARDED.value
    }
    target_tier: str = tier_mapping[tier_type]

    async with db_manager.session_factory() as db_session:
        query = (
            select(ProxyMetricModel.proxy_endpoint)
            .where(ProxyMetricModel.session_id == session_id)
            .where(ProxyMetricModel.tier == target_tier)
        )
        result = await db_session.execute(query)
        proxy_lines: list[str] = [row[0] for row in result.all()]

    return PlainTextResponse(
        content="\n".join(proxy_lines),
        media_type="text/plain",
        headers={"Content-Disposition": f"attachment; filename={tier_type}_{session_id[:8]}.txt"}
    )