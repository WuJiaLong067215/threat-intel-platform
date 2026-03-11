"""
FastAPI 应用 - 威胁情报平台 API v4.0

改进：
- API Key 认证中间件
- 结构化日志
- 统一的 CVE 总数统计（不依赖前端 limit）
- 更完善的错误处理
"""
import os
import logging
import sys
from datetime import datetime
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Depends, Security, Query
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.security import APIKeyHeader
from pydantic import BaseModel
from typing import Optional

from database.db_manager import (
    find_cves, find_cve_by_id, get_cve_stats, get_dashboard_stats,
    get_all_assets, add_asset_to_db, remove_asset_from_db,
    find_risks, get_risk_stats, get_latest_reports,
    upsert_cves, upsert_risks, save_report_to_db,
)
from analyzer.vuln_analyzer import generate_summary
from analyzer.asset_matcher import match_assets
from analyzer.risk_engine import rank_cves
from analyzer.exploit_detector import check_exploit
from crawler.nvd_crawler import fetch_recent_cves, parse_cve_data, fetch_all_cves
from crawler.asset_scanner import scan_host, import_scan_results
from core.intel_engine import run_full_pipeline, get_system_status
from report.report_generator import generate_daily_brief, generate_json_report
from scheduler.job import start as start_scheduler, stop as stop_scheduler, get_status as scheduler_status

# ── 日志 ──
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("memory/app.log", encoding="utf-8"),
    ],
)
logger = logging.getLogger("app")

# ── API Key 认证 ──
API_KEY = os.getenv("API_KEY", "")
API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)


async def verify_api_key(api_key: str = Security(API_KEY_HEADER)):
    """API Key 验证（未配置则跳过，方便开发）"""
    if API_KEY and api_key != API_KEY:
        raise HTTPException(status_code=401, detail="无效的 API Key")
    return True


# ── 应用生命周期 ──
@asynccontextmanager
async def lifespan(app: FastAPI):
    # 启动时
    logger.info("🛡️ 威胁情报平台启动中...")
    from database.db_manager import test_connection, init_collections
    if not test_connection():
        logger.error("❌ 数据库未就绪")
    else:
        init_collections()
    start_scheduler()
    yield
    # 关闭时
    stop_scheduler()
    logger.info("🛡️ 威胁情报平台已关闭")


app = FastAPI(title="威胁情报平台", version="4.0.0", lifespan=lifespan)


# ── 数据模型 ──

class AssetInput(BaseModel):
    product: str
    version: str = "unknown"
    host: str = ""
    department: str = ""


class ScanInput(BaseModel):
    hosts: list[str]
    timeout: int = 1


class PipelineInput(BaseModel):
    days_back: int = 7
    check_exploit: bool = True


# ── 系统 ──

@app.get("/api/health")
def health():
    return {"status": "ok", "message": "🛡️ 威胁情报平台运行中"}


@app.get("/api/status")
def system_status():
    status = get_system_status()
    status["scheduler"] = scheduler_status()
    return status


# ── Dashboard ──

@app.get("/api/dashboard")
def dashboard():
    return get_dashboard_stats()


# ── CVE 情报 ──

@app.get("/api/cves")
def list_cves(
    limit: int = Query(default=100, le=500),
    skip: int = 0,
    severity: str = None,
    has_exploit: bool = None,
):
    query = {}
    if severity:
        query["severity"] = severity.upper()
    if has_exploit:
        query["exploit.has_exploit"] = True
    cves = find_cves(query=query, limit=limit, skip=skip)
    # 总数独立查询，不受 limit 影响
    from database.db_manager import get_db
    total = get_db()["cves"].count_documents(query)
    return {"total": total, "data": cves}


@app.get("/api/cves/{cve_id}")
def get_cve(cve_id: str):
    cve = find_cve_by_id(cve_id)
    if not cve:
        raise HTTPException(status_code=404, detail=f"CVE {cve_id} 不存在")
    return cve


@app.get("/api/cves/stats")
def cve_statistics():
    return get_cve_stats()


@app.get("/api/summary")
def summary():
    cves = find_cves(limit=500)
    return generate_summary(cves)


@app.get("/api/risk-ranking")
def risk_ranking(top_n: int = Query(default=10, le=50)):
    cves = find_cves(limit=500)
    ranked = rank_cves(cves, top_n=top_n)
    return {"total": len(ranked), "data": ranked}


# ── Exploit ──

@app.get("/api/exploit/{cve_id}")
def exploit_check(cve_id: str):
    result = check_exploit(cve_id)
    return {"cve_id": cve_id, **result}


# ── 资产 ──

@app.get("/api/assets")
def list_assets():
    assets = get_all_assets()
    return {"total": len(assets), "assets": assets}


@app.post("/api/assets")
def add_asset_endpoint(asset: AssetInput, _auth: bool = Depends(verify_api_key)):
    result = add_asset_to_db(asset.product, asset.version, asset.host, asset.department)
    return {"status": result, "product": asset.product, "version": asset.version}


@app.delete("/api/assets/{product}")
def remove_asset_endpoint(product: str, _auth: bool = Depends(verify_api_key)):
    result = remove_asset_from_db(product)
    if not result:
        raise HTTPException(status_code=404, detail=f"资产 '{product}' 不存在")
    return {"status": "removed", "product": product}


# ── 资产扫描（需要认证，高危操作） ──

@app.post("/api/scan")
def scan_hosts(input_data: ScanInput, _auth: bool = Depends(verify_api_key)):
    results = []
    for host in input_data.hosts:
        result = scan_host(host, timeout=input_data.timeout)
        results.append(result)
    import_result = import_scan_results(results)
    return import_result


# ── 风险 ──

@app.get("/api/risks")
def list_risks(limit: int = Query(default=50, le=200)):
    risks = find_risks(limit=limit)
    return {"total": len(risks), "data": risks}


@app.get("/api/risks/stats")
def risk_statistics():
    return get_risk_stats()


# ── 报告 ──

@app.get("/api/reports")
def list_reports(limit: int = 10):
    reports = get_latest_reports(limit=limit)
    return {"total": len(reports), "data": reports}


@app.get("/api/brief")
def get_brief():
    cves = find_cves(limit=500)
    summary = generate_summary(cves)
    alerts = match_assets(cves)
    ranked = rank_cves(cves, top_n=10)
    brief = generate_daily_brief(summary, alerts, ranked)
    return {
        "text": brief,
        "json": generate_json_report(summary, alerts, ranked),
    }


# ── 同步 ──

@app.post("/api/sync")
def sync_cves(days_back: int = 7, full: bool = False, _auth: bool = Depends(verify_api_key)):
    """
    同步 CVE 数据
    - full=true: 分页拉取全量（最多500条）
    - full=false: 单页拉取（兼容旧逻辑）
    """
    if full:
        vulns = fetch_all_cves(days_back=days_back, max_total=500)
        if not vulns:
            return {"status": "error", "message": "同步失败"}
        parsed = parse_cve_data(vulns)
    else:
        raw = fetch_recent_cves(days_back=days_back, results_per_page=100)
        if not raw:
            return {"status": "error", "message": "同步失败"}
        parsed = parse_cve_data(raw)

    if parsed:
        upsert_cves(parsed)
    return {"status": "ok", "synced": len(parsed)}


@app.post("/api/pipeline")
def run_pipeline(input_data: PipelineInput = PipelineInput(), _auth: bool = Depends(verify_api_key)):
    """手动触发完整流水线"""
    result = run_full_pipeline(
        days_back=input_data.days_back,
        check_exploit_flag=input_data.check_exploit,
    )
    return result


# ── Web 前端 ──

WEB_DIR = os.path.join(os.path.dirname(__file__), "..", "web")
app.mount("/static", StaticFiles(directory=WEB_DIR), name="static")


@app.get("/")
def serve_index():
    return FileResponse(os.path.join(WEB_DIR, "index.html"))
