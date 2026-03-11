"""
FastAPI 应用 - 威胁情报平台 API v5.0

Phase 1 新增：
- JWT 用户认证（登录/注册/权限管理）
- CNVD / GitHub Advisory 数据源
- 资产批量导入（CSV/Excel）
- 审计日志
"""
import os
import logging
import sys
from datetime import datetime
from contextlib import asynccontextmanager
from io import BytesIO

from fastapi import FastAPI, HTTPException, Depends, Query, UploadFile, File, Security
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials, APIKeyHeader
from pydantic import BaseModel
from typing import Optional

from database.db_manager import (
    find_cves, find_cve_by_id, get_cve_stats, get_dashboard_stats,
    get_all_assets, add_asset_to_db, remove_asset_from_db,
    find_risks, get_risk_stats, get_latest_reports,
    upsert_cves, upsert_risks, save_report_to_db, get_db,
)
from analyzer.vuln_analyzer import generate_summary
from analyzer.asset_matcher import match_assets
from analyzer.risk_engine import rank_cves
from analyzer.exploit_detector import check_exploit
from analyzer.asset_import import parse_csv, parse_excel, import_assets, generate_csv_template
from crawler.nvd_crawler import fetch_recent_cves, parse_cve_data, fetch_all_cves
from crawler.cnvd_crawler import fetch_cnvd_list
from crawler.github_advisory import fetch_github_advisories
from crawler.asset_scanner import scan_host, import_scan_results
from core.intel_engine import run_full_pipeline, get_system_status
from core.auth import (
    authenticate, register_user, list_users, delete_user, change_password,
    init_default_admin, get_current_user, get_optional_user, has_permission,
    create_token,
)
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

# ── 兼容旧 API Key（可和 JWT 共存） ──
API_KEY = os.getenv("API_KEY", "")
API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)
security_bearer = HTTPBearer(auto_error=False)


async def verify_api_key(api_key: str = Security(API_KEY_HEADER)):
    """旧版 API Key 验证（兼容）"""
    if API_KEY and api_key != API_KEY:
        raise HTTPException(status_code=401, detail="无效的 API Key")
    return True


# ── 审计日志 ──
AUDIT_COL = "audit_logs"


def write_audit_log(username: str, action: str, detail: str = "", level: str = "info"):
    """写入审计日志"""
    try:
        get_db()[AUDIT_COL].insert_one({
            "username": username,
            "action": action,
            "detail": detail,
            "level": level,
            "timestamp": datetime.utcnow().isoformat(),
        })
    except Exception:
        pass


# ── 权限检查 ──
WRITE_PERMISSIONS = ["admin", "analyst"]
DELETE_PERMISSIONS = ["admin"]


# ── 应用生命周期 ──
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("🛡️ 威胁情报平台启动中...")
    from database.db_manager import test_connection, init_collections
    if not test_connection():
        logger.error("❌ 数据库未就绪")
    else:
        init_collections()
        init_default_admin()
    start_scheduler()
    yield
    stop_scheduler()
    logger.info("🛡️ 威胁情报平台已关闭")


app = FastAPI(title="威胁情报平台", version="5.0.0", lifespan=lifespan)


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


class LoginInput(BaseModel):
    username: str
    password: str


class RegisterInput(BaseModel):
    username: str
    password: str
    role: str = "viewer"
    department: str = ""


class ChangePasswordInput(BaseModel):
    old_password: str
    new_password: str


# ═══════════════════════════════════
# 认证接口
# ═══════════════════════════════════

@app.post("/api/auth/login")
def login(data: LoginInput):
    result, error = authenticate(data.username, data.password)
    if error:
        raise HTTPException(status_code=401, detail=error)
    write_audit_log(data.username, "login", "用户登录")
    return result


@app.post("/api/auth/register")
def register(data: RegisterInput, user=Depends(get_current_user)):
    if user.get("role") not in DELETE_PERMISSIONS:
        raise HTTPException(status_code=403, detail="仅管理员可创建用户")
    result, error = register_user(data.username, data.password, data.role, data.department)
    if error:
        raise HTTPException(status_code=400, detail=error)
    write_audit_log(user["sub"], "register", f"创建用户: {data.username} ({data.role})")
    return result


@app.post("/api/auth/change-password")
def change_pwd(data: ChangePasswordInput, user=Depends(get_current_user)):
    ok, error = change_password(user["sub"], data.old_password, data.new_password)
    if not ok:
        raise HTTPException(status_code=400, detail=error)
    write_audit_log(user["sub"], "change_password", "修改密码")
    return {"status": "ok"}


@app.get("/api/auth/me")
def get_me(user=Depends(get_current_user)):
    return {"username": user["sub"], "role": user["role"]}


@app.get("/api/auth/users")
def get_users(user=Depends(get_current_user)):
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="仅管理员可查看")
    return {"users": list_users()}


@app.delete("/api/auth/users/{username}")
def remove_user(username: str, user=Depends(get_current_user)):
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="仅管理员可删除")
    ok, error = delete_user(username)
    if not ok:
        raise HTTPException(status_code=400, detail=error)
    write_audit_log(user["sub"], "delete_user", f"删除用户: {username}")
    return {"status": "ok"}


# ═══════════════════════════════════
# 系统
# ═══════════════════════════════════

@app.get("/api/health")
def health():
    return {"status": "ok", "message": "🛡️ 威胁情报平台运行中", "version": "5.0.0"}


@app.get("/api/status")
def system_status(user=Depends(get_optional_user)):
    status = get_system_status()
    status["scheduler"] = scheduler_status()
    return status


# ═══════════════════════════════════
# Dashboard
# ═══════════════════════════════════

@app.get("/api/dashboard")
def dashboard(user=Depends(get_optional_user)):
    return get_dashboard_stats()


# ═══════════════════════════════════
# CVE 情报
# ═══════════════════════════════════

@app.get("/api/cves")
def list_cves(
    limit: int = Query(default=100, le=500),
    skip: int = 0,
    severity: str = None,
    has_exploit: bool = None,
    source: str = None,
    user=Depends(get_optional_user),
):
    query = {}
    if severity:
        query["severity"] = severity.upper()
    if has_exploit:
        query["exploit.has_exploit"] = True
    if source:
        query["source"] = source.upper()
    cves = find_cves(query=query, limit=limit, skip=skip)
    total = get_db()["cves"].count_documents(query)
    return {"total": total, "data": cves}


@app.get("/api/cves/{cve_id}")
def get_cve(cve_id: str, user=Depends(get_optional_user)):
    cve = find_cve_by_id(cve_id)
    if not cve:
        raise HTTPException(status_code=404, detail=f"CVE {cve_id} 不存在")
    return cve


@app.get("/api/cves/stats")
def cve_statistics(user=Depends(get_optional_user)):
    return get_cve_stats()


@app.get("/api/summary")
def summary(user=Depends(get_optional_user)):
    cves = find_cves(limit=500)
    return generate_summary(cves)


@app.get("/api/risk-ranking")
def risk_ranking(top_n: int = Query(default=10, le=50), user=Depends(get_optional_user)):
    cves = find_cves(limit=500)
    ranked = rank_cves(cves, top_n=top_n)
    return {"total": len(ranked), "data": ranked}


# ═══════════════════════════════════
# Exploit
# ═══════════════════════════════════

@app.get("/api/exploit/{cve_id}")
def exploit_check(cve_id: str, user=Depends(get_optional_user)):
    result = check_exploit(cve_id)
    return {"cve_id": cve_id, **result}


# ═══════════════════════════════════
# 资产
# ═══════════════════════════════════

@app.get("/api/assets")
def list_assets(user=Depends(get_optional_user)):
    assets = get_all_assets()
    return {"total": len(assets), "assets": assets}


@app.post("/api/assets")
def add_asset_endpoint(asset: AssetInput, user=Depends(get_current_user)):
    if user.get("role") not in WRITE_PERMISSIONS:
        raise HTTPException(status_code=403, detail="权限不足")
    result = add_asset_to_db(asset.product, asset.version, asset.host, asset.department)
    write_audit_log(user["sub"], "add_asset", f"{asset.product} {asset.version}")
    return {"status": result, "product": asset.product, "version": asset.version}


@app.delete("/api/assets/{product}")
def remove_asset_endpoint(product: str, user=Depends(get_current_user)):
    if user.get("role") not in DELETE_PERMISSIONS:
        raise HTTPException(status_code=403, detail="权限不足")
    result = remove_asset_from_db(product)
    if not result:
        raise HTTPException(status_code=404, detail=f"资产 '{product}' 不存在")
    write_audit_log(user["sub"], "remove_asset", product)
    return {"status": "removed", "product": product}


@app.post("/api/assets/import/csv")
def import_assets_csv(user=Depends(get_current_user)):
    """下载 CSV 导入模板"""
    from fastapi.responses import PlainTextResponse
    return PlainTextResponse(
        content=generate_csv_template(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=asset_template.csv"},
    )


@app.post("/api/assets/upload/csv")
async def upload_csv(file: UploadFile = File(...), user=Depends(get_current_user)):
    """上传 CSV 文件批量导入"""
    if user.get("role") not in WRITE_PERMISSIONS:
        raise HTTPException(status_code=403, detail="权限不足")
    try:
        content = (await file.read()).decode("utf-8")
        assets = parse_csv(content)
        if not assets:
            raise HTTPException(status_code=400, detail="CSV 为空或格式错误")
        stats = import_assets(assets, source="csv")
        write_audit_log(user["sub"], "import_assets_csv", f"导入 {stats['added']} 条")
        return stats
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="文件编码错误，请使用 UTF-8")


@app.post("/api/assets/upload/excel")
async def upload_excel(file: UploadFile = File(...), user=Depends(get_current_user)):
    """上传 Excel 文件批量导入"""
    if user.get("role") not in WRITE_PERMISSIONS:
        raise HTTPException(status_code=403, detail="权限不足")
    import tempfile
    try:
        content = await file.read()
        with tempfile.NamedTemporaryFile(suffix=".xlsx", delete=False) as tmp:
            tmp.write(content)
            tmp_path = tmp.name
        assets = parse_excel(tmp_path)
        if not assets:
            raise HTTPException(status_code=400, detail="Excel 为空或格式错误")
        stats = import_assets(assets, source="excel")
        write_audit_log(user["sub"], "import_assets_excel", f"导入 {stats['added']} 条")
        return stats
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Excel 解析失败: {e}")


# ═══════════════════════════════════
# 资产扫描
# ═══════════════════════════════════

@app.post("/api/scan")
def scan_hosts(input_data: ScanInput, user=Depends(get_current_user)):
    if user.get("role") not in WRITE_PERMISSIONS:
        raise HTTPException(status_code=403, detail="权限不足")
    results = []
    for host in input_data.hosts:
        result = scan_host(host, timeout=input_data.timeout)
        results.append(result)
    import_result = import_scan_results(results)
    write_audit_log(user["sub"], "scan_hosts", f"扫描 {len(input_data.hosts)} 台主机")
    return import_result


# ═══════════════════════════════════
# 风险
# ═══════════════════════════════════

@app.get("/api/risks")
def list_risks(limit: int = Query(default=50, le=200), user=Depends(get_optional_user)):
    risks = find_risks(limit=limit)
    return {"total": len(risks), "data": risks}


@app.get("/api/risks/stats")
def risk_statistics(user=Depends(get_optional_user)):
    return get_risk_stats()


# ═══════════════════════════════════
# 报告
# ═══════════════════════════════════

@app.get("/api/reports")
def list_reports(limit: int = 10, user=Depends(get_optional_user)):
    reports = get_latest_reports(limit=limit)
    return {"total": len(reports), "data": reports}


@app.get("/api/brief")
def get_brief(user=Depends(get_optional_user)):
    cves = find_cves(limit=500)
    summary = generate_summary(cves)
    alerts = match_assets(cves)
    ranked = rank_cves(cves, top_n=10)
    brief = generate_daily_brief(summary, alerts, ranked)
    return {
        "text": brief,
        "json": generate_json_report(summary, alerts, ranked),
    }


# ═══════════════════════════════════
# 同步
# ═══════════════════════════════════

@app.post("/api/sync")
def sync_cves(
    days_back: int = 7,
    full: bool = True,
    sources: str = "nvd",
    user=Depends(get_current_user),
):
    """
    同步 CVE 数据
    - sources: 逗号分隔的数据源，如 "nvd,cnvd,github"
    - full=true: 分页拉取全量
    """
    if user.get("role") not in WRITE_PERMISSIONS:
        raise HTTPException(status_code=403, detail="权限不足")

    source_list = [s.strip().lower() for s in sources.split(",")]
    total_synced = 0
    errors = []

    for source in source_list:
        try:
            if source == "nvd":
                if full:
                    vulns = fetch_all_cves(days_back=days_back, max_total=500)
                else:
                    raw = fetch_recent_cves(days_back=days_back, results_per_page=100)
                    vulns = raw.get("vulnerabilities", []) if raw else []
                parsed = parse_cve_data(vulns)
                count = upsert_cves(parsed) if parsed else 0
                total_synced += count
                write_audit_log(user["sub"], "sync_nvd", f"NVD 同步 {count} 条")

            elif source == "cnvd":
                cnvd_list = fetch_cnvd_list(days_back=days_back)
                if cnvd_list:
                    count = upsert_cves(cnvd_list)
                    total_synced += count
                write_audit_log(user["sub"], "sync_cnvd", f"CNVD 同步 {len(cnvd_list)} 条")

            elif source == "github":
                gh_list = fetch_github_advisories(days_back=min(days_back, 30))
                if gh_list:
                    count = upsert_cves(gh_list)
                    total_synced += count
                write_audit_log(user["sub"], "sync_github", f"GitHub Advisory 同步 {len(gh_list)} 条")

            else:
                errors.append(f"未知数据源: {source}")

        except Exception as e:
            errors.append(f"{source}: {str(e)}")
            logger.error(f"同步 {source} 失败: {e}")

    return {
        "status": "ok" if not errors else "partial",
        "synced": total_synced,
        "sources": source_list,
        "errors": errors,
    }


@app.post("/api/pipeline")
def run_pipeline(input_data: PipelineInput = PipelineInput(), user=Depends(get_current_user)):
    if user.get("role") not in WRITE_PERMISSIONS:
        raise HTTPException(status_code=403, detail="权限不足")
    result = run_full_pipeline(
        days_back=input_data.days_back,
        check_exploit_flag=input_data.check_exploit,
    )
    write_audit_log(user["sub"], "pipeline", f"流水线: {result['status']}")
    return result


# ═══════════════════════════════════
# 审计日志
# ═══════════════════════════════════

@app.get("/api/audit/logs")
def get_audit_logs(
    limit: int = Query(default=50, le=200),
    user=Depends(get_current_user),
):
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="仅管理员可查看")
    logs = list(
        get_db()[AUDIT_COL]
        .find({}, {"_id": 0})
        .sort("timestamp", -1)
        .limit(limit)
    )
    return {"total": len(logs), "logs": logs}


# ── Web 前端 ──

WEB_DIR = os.path.join(os.path.dirname(__file__), "..", "web")
app.mount("/static", StaticFiles(directory=WEB_DIR), name="static")


@app.get("/")
def serve_index():
    return FileResponse(os.path.join(WEB_DIR, "index.html"))
