"""FastAPI REST routes and endpoint handlers."""

import time
import io
import csv
import logging
from typing import Optional, List, Dict, Any
from fastapi import APIRouter, Request, Query, Response, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse

from procpulse.api.websocket import ws_manager

logger = logging.getLogger(__name__)

router = APIRouter()
START_TIME = time.time()


@router.get("/api/health")
async def get_health(request: Request) -> Dict[str, Any]:
    """Retrieve system health score, status, agent uptime, and self-overhead."""
    db = getattr(request.app.state, "db", None)
    engine = getattr(request.app.state, "engine", None)
    collector = getattr(request.app.state, "system_collector", None)

    health_score = 100.0
    health_status = "healthy"
    anomalies_count = 0
    suspicious_count = 0

    if engine:
        health_score, health_status = engine.get_health_score()
        anomalies_count = len(engine.get_active_anomalies())
        suspicious_count = len(engine.get_suspicious_processes())

    overhead_cpu = 0.0
    overhead_mem = 0
    if collector:
        try:
            overhead_cpu = round(getattr(collector, "_last_overhead_cpu", 0.0), 2)
            if hasattr(collector, "_self_process"):
                overhead_mem = collector._self_process.memory_info().rss
        except Exception:
            pass

    return {
        "status": "ok",
        "health_score": round(health_score, 1),
        "health_status": health_status,
        "uptime_seconds": round(time.time() - START_TIME, 1),
        "active_anomalies_count": anomalies_count,
        "suspicious_processes_count": suspicious_count,
        "overhead": {
            "cpu_percent": overhead_cpu,
            "memory_rss_bytes": overhead_mem,
            "memory_rss_mb": round(overhead_mem / (1024 * 1024), 2),
        },
    }


@router.get("/api/metrics")
async def get_metrics(
    request: Request,
    limit: int = Query(default=60, ge=1, le=1000),
    since: Optional[float] = Query(default=None),
) -> List[Dict[str, Any]]:
    """Retrieve historical system performance time-series."""
    db = getattr(request.app.state, "db", None)
    if not db:
        return []
    return db.get_system_metrics(limit=limit, since=since)


@router.get("/api/processes")
async def get_processes(
    request: Request,
    limit: int = Query(default=15, ge=1, le=100),
) -> List[Dict[str, Any]]:
    """Retrieve the latest snapshot of top resource-consuming processes."""
    db = getattr(request.app.state, "db", None)
    if not db:
        return []
    return db.get_recent_processes(limit=limit)


@router.get("/api/anomalies")
async def get_anomalies(
    request: Request,
    limit: int = Query(default=50, ge=1, le=500),
    severity: Optional[str] = Query(default=None),
    since: Optional[float] = Query(default=None),
) -> List[Dict[str, Any]]:
    """Retrieve detected anomaly events with optional severity filter."""
    db = getattr(request.app.state, "db", None)
    if not db:
        return []
    return db.get_anomalies(limit=limit, severity=severity, since=since)


@router.get("/api/suspicious")
async def get_suspicious(request: Request) -> List[Dict[str, Any]]:
    """Retrieve currently flagged suspicious processes (fd leaks, rapid growth)."""
    engine = getattr(request.app.state, "engine", None)
    if not engine:
        return []
    return engine.get_suspicious_processes()


@router.get("/api/reports/export.csv")
async def export_csv_report(request: Request) -> Response:
    """Export recent anomaly events and telemetry snapshots as a CSV file."""
    db = getattr(request.app.state, "db", None)
    anomalies = db.get_anomalies(limit=500) if db else []

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "Timestamp",
        "Metric",
        "Severity",
        "Score",
        "Value",
        "Baseline",
        "Z-Score",
        "PID",
        "Process",
        "Explanation",
    ])
    for a in anomalies:
        writer.writerow([
            time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(a["timestamp"])),
            a["metric"],
            a["severity"],
            round(a["score"], 3),
            round(a["value"], 2),
            round(a["baseline"], 2),
            round(a["z_score"], 2),
            a.get("related_pid") or "",
            a.get("related_process") or "",
            a["explanation"],
        ])

    csv_data = output.getvalue()
    return Response(
        content=csv_data,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=procpulse_anomalies.csv"},
    )


@router.get("/api/reports/incident", response_class=HTMLResponse)
async def generate_incident_report(request: Request) -> HTMLResponse:
    """Generate a print-ready executive incident report summary."""
    db = getattr(request.app.state, "db", None)
    engine = getattr(request.app.state, "engine", None)

    health_score = 100.0
    health_status = "healthy"
    if engine:
        health_score, health_status = engine.get_health_score()

    anomalies = db.get_anomalies(limit=50) if db else []
    recent_metrics = db.get_system_metrics(limit=1) if db else []
    latest_metric = recent_metrics[-1] if recent_metrics else {}

    rows_html = ""
    for a in anomalies:
        sev_color = "#dc3545" if a["severity"] == "high" else ("#ffc107" if a["severity"] == "medium" else "#17a2b8")
        dt_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(a["timestamp"]))
        rows_html += f"""
        <tr>
            <td>{dt_str}</td>
            <td><strong style="color: {sev_color}; text-transform: uppercase;">{a['severity']}</strong></td>
            <td>{a['metric']}</td>
            <td>{round(a['value'], 1)} (Base: {round(a['baseline'], 1)})</td>
            <td>{round(a['z_score'], 1)}σ</td>
            <td>{a.get('related_process') or 'System'} (PID {a.get('related_pid') or 'N/A'})</td>
            <td>{a['explanation']}</td>
        </tr>
        """

    html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>ProcPulse AI — Incident & Telemetry Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 40px; color: #222; background: #fff; }}
        h1 {{ margin-bottom: 4px; color: #111; }}
        .header {{ border-bottom: 2px solid #0066cc; padding-bottom: 12px; margin-bottom: 24px; }}
        .stats-grid {{ display: flex; gap: 20px; margin-bottom: 24px; }}
        .stat-card {{ border: 1px solid #ddd; padding: 14px 20px; border-radius: 6px; background: #f9f9f9; flex: 1; }}
        .stat-card h3 {{ margin: 0 0 8px 0; font-size: 13px; color: #666; text-transform: uppercase; }}
        .stat-card .val {{ font-size: 24px; font-weight: bold; color: #0066cc; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; font-size: 13px; }}
        th, td {{ border: 1px solid #ddd; padding: 10px; text-align: left; }}
        th {{ background: #f2f2f2; }}
        @media print {{
            body {{ margin: 10px; }}
            .no-print {{ display: none; }}
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>ProcPulse AI — Incident & Telemetry Audit Report</h1>
        <p>Generated: {time.strftime("%Y-%m-%d %H:%M:%S")} | Machine Telemetry Snapshot</p>
    </div>
    <div class="stats-grid">
        <div class="stat-card">
            <h3>System Health Score</h3>
            <div class="val">{round(health_score, 1)} / 100 ({health_status.upper()})</div>
        </div>
        <div class="stat-card">
            <h3>CPU Utilization</h3>
            <div class="val">{latest_metric.get('cpu_percent', 0.0)}%</div>
        </div>
        <div class="stat-card">
            <h3>Memory Usage</h3>
            <div class="val">{latest_metric.get('mem_percent', 0.0)}%</div>
        </div>
        <div class="stat-card">
            <h3>Total Recorded Anomalies</h3>
            <div class="val">{len(anomalies)}</div>
        </div>
    </div>
    <h2>Incident Timeline & Anomaly Log</h2>
    <table>
        <thead>
            <tr>
                <th>Time</th>
                <th>Severity</th>
                <th>Metric</th>
                <th>Observed (Baseline)</th>
                <th>Z-Score</th>
                <th>Origin Process</th>
                <th>Plain-English Diagnostic</th>
            </tr>
        </thead>
        <tbody>
            {rows_html if rows_html else '<tr><td colspan="7">No anomalies recorded in the selected window.</td></tr>'}
        </tbody>
    </table>
    <br/>
    <button class="no-print" onclick="window.print()" style="padding: 10px 18px; background: #0066cc; color: white; border: none; border-radius: 4px; cursor: pointer;">Print / Save as PDF</button>
</body>
</html>
"""
    return HTMLResponse(content=html)


@router.websocket("/ws/live")
async def websocket_live_endpoint(websocket: WebSocket) -> None:
    """Real-time WebSocket endpoint for streaming 1-second telemetry."""
    await ws_manager.connect(websocket)
    try:
        while True:
            # Keep connection open; receive client pings/messages if sent
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception as e:
        logger.debug("WebSocket exception: %s", e)
        ws_manager.disconnect(websocket)
