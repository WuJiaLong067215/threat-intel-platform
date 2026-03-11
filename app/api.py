"""
FastAPI 应用 - 威胁情报平台 API v3.0 + Web 前端
"""
from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import Optional
from datetime import datetime
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
from crawler.nvd_crawler import fetch_recent_cves, parse_cve_data
from crawler.asset_scanner import scan_host, import_scan_results
from core.intel_engine import run_full_pipeline, get_system_status
from report.report_generator import generate_daily_brief, generate_json_report

import os

app = FastAPI(title="威胁情报平台", version="3.0.0")


# ── 数据模型 ──

class AssetInput(BaseModel):
    product: str
    version: str = "unknown"
    host: str = ""
    department: str = ""


class ScanInput(BaseModel):
    hosts: list[str]
    timeout: int = 1


# ── 系统 ──

@app.get("/api/health")
def health():
    return {"status": "ok", "message": "🛡️ 威胁情报平台运行中"}


@app.get("/api/status")
def system_status():
    return get_system_status()


# ── Dashboard ──

@app.get("/api/dashboard")
def dashboard():
    return get_dashboard_stats()


# ── CVE 情报 ──

@app.get("/api/cves")
def list_cves(limit: int = 100, skip: int = 0, severity: str = None, has_exploit: bool = None):
    query = {}
    if severity:
        query["severity"] = severity.upper()
    if has_exploit:
        query["exploit.has_exploit"] = True
    cves = find_cves(query=query, limit=limit, skip=skip)
    total = len(cves)
    return {"total": total, "data": cves}


@app.get("/api/cves/{cve_id}")
def get_cve(cve_id: str):
    cve = find_cve_by_id(cve_id)
    if not cve:
        raise HTTPException(status_code=404, detail=f"CVE {cve_id} 不存在")
    # 移除 _id
    cve.pop("_id", None)
    return cve


@app.get("/api/cves/stats")
def cve_statistics():
    return get_cve_stats()


@app.get("/api/summary")
def summary():
    cves = find_cves(limit=200)
    return generate_summary(cves)


@app.get("/api/risk-ranking")
def risk_ranking(top_n: int = 10):
    cves = find_cves(limit=200)
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
def add_asset_endpoint(asset: AssetInput):
    result = add_asset_to_db(asset.product, asset.version, asset.host, asset.department)
    return {"status": result, "product": asset.product, "version": asset.version}


@app.delete("/api/assets/{product}")
def remove_asset_endpoint(product: str):
    result = remove_asset_from_db(product)
    if not result:
        raise HTTPException(status_code=404, detail=f"资产 '{product}' 不存在")
    return {"status": "removed", "product": product}


# ── 资产扫描 ──

@app.post("/api/scan")
def scan_hosts(input_data: ScanInput):
    results = []
    for host in input_data.hosts:
        result = scan_host(host, timeout=input_data.timeout)
        results.append(result)
    import_result = import_scan_results(results)
    return import_result


# ── 风险 ──

@app.get("/api/risks")
def list_risks(limit: int = 50):
    risks = find_risks(limit=limit)
    for r in risks:
        r.pop("_id", None)
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
    cves = find_cves(limit=200)
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
def sync_cves(days_back: int = 7):
    raw = fetch_recent_cves(days_back=days_back)
    if not raw:
        return {"status": "error", "message": "同步失败"}
    parsed = parse_cve_data(raw)
    if parsed:
        upsert_cves(parsed)
    return {"status": "ok", "synced": len(parsed)}


@app.post("/api/pipeline")
def run_pipeline(days_back: int = 7):
    """手动触发完整流水线"""
    result = run_full_pipeline(days_back=days_back, check_exploit_flag=True)
    return result


# ── Web 前端 ──

WEB_DIR = os.path.join(os.path.dirname(__file__), "..", "web")
app.mount("/static", StaticFiles(directory=WEB_DIR), name="static")


@app.get("/")
def serve_index():
    return FileResponse(os.path.join(WEB_DIR, "index.html"))
