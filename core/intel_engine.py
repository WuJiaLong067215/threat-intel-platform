"""
情报引擎 - 核心编排层（v2.0）

统一编排：采集 → 分析 → Exploit → 资产匹配 → 风险评分 → 存储 → 报告

改进：
- 使用 fetch_all_cves 全量拉取
- 适配新的 asset_matcher 和 db_manager 接口
- 结构化日志
"""
import logging
from datetime import datetime

from crawler.nvd_crawler import fetch_all_cves, parse_cve_data
from analyzer.vuln_analyzer import generate_summary
from analyzer.exploit_detector import batch_check_exploits
from analyzer.asset_matcher import match_assets
from analyzer.risk_engine import rank_cves
from report.report_generator import generate_daily_brief, save_report as save_file
from database.db_manager import (
    upsert_cves, upsert_risks, save_report_to_db,
    find_cves, get_dashboard_stats,
)

logger = logging.getLogger(__name__)


def run_full_pipeline(days_back=7, check_exploit_flag=True, limit=500):
    """
    执行完整的情报流水线

    Args:
        days_back: 回溯天数
        check_exploit_flag: 是否检测 Exploit
        limit: 最多采集数量

    Returns:
        dict: 流水线执行结果
    """
    start_time = datetime.now()
    logger.info(f"{'='*60}")
    logger.info(f"🔄 情报引擎启动 | {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    logger.info(f"{'='*60}")

    result = {
        "status": "running",
        "started_at": start_time.isoformat(),
        "cves_collected": 0,
        "exploits_checked": 0,
        "exploits_found": 0,
        "asset_hits": 0,
        "risks_written": 0,
        "errors": [],
    }

    # ── Step 1: 全量采集 ──
    logger.info("📡 Step 1: 采集 CVE 情报（全量分页）...")
    vulns = fetch_all_cves(days_back=days_back, max_total=limit)
    if not vulns:
        result["status"] = "failed"
        result["errors"].append("NVD API 采集失败")
        result["finished_at"] = datetime.now().isoformat()
        return result

    cves = parse_cve_data(vulns)
    result["cves_collected"] = len(cves)
    logger.info(f"   获取 {len(cves)} 条 CVE")

    # ── Step 2: Exploit 检测 ──
    if check_exploit_flag:
        logger.info("🔥 Step 2: Exploit 检测...")
        cves = batch_check_exploits(cves, max_workers=3, delay=1.0)
        result["exploits_checked"] = sum(
            1 for c in cves
            if isinstance(c.get("exploit"), dict) and c["exploit"].get("has_exploit")
        )
        result["exploits_found"] = result["exploits_checked"]
    else:
        for c in cves:
            c.setdefault("exploit", {"has_exploit": False, "source": None, "details": "未检测"})

    # ── Step 3: 资产匹配 ──
    logger.info("🎯 Step 3: 资产匹配...")
    alerts = match_assets(cves)
    result["asset_hits"] = len(alerts)

    # ── Step 4: 风险评分 ──
    logger.info("⚡ Step 4: 风险评分...")
    ranked = rank_cves(cves, top_n=50)

    # ── Step 5: 生成报告 ──
    logger.info("📊 Step 5: 生成简报...")
    summary = generate_summary(cves)
    brief = generate_daily_brief(summary, alerts, ranked)
    logger.info(brief[:500] + "...")

    # ── Step 6: 写入数据库 ──
    logger.info("💾 Step 6: 写入数据库...")
    cve_count = upsert_cves(cves)

    risk_records = []
    for alert in alerts:
        risk_records.append({
            "cve_id": alert["cve_id"],
            "product": alert["product"],
            "version": alert.get("version", "unknown"),
            "severity": alert.get("severity", "unknown"),
            "score": alert.get("score", 0),
            "match_method": alert.get("match_method", "unknown"),
            "risk_score": next(
                (r["risk_score"] for r in ranked if r["cve_id"] == alert["cve_id"]), 0
            ),
            "risk_level": next(
                (r["risk_level"] for r in ranked if r["cve_id"] == alert["cve_id"]), "UNKNOWN"
            ),
            "exploit": alert.get("exploit", {}),
        })
    risk_count = upsert_risks(risk_records)
    result["risks_written"] = risk_count

    save_report_to_db({
        "date": datetime.now().strftime("%Y-%m-%d"),
        "total_cves": len(cves),
        "high_risk": summary.get("high_risk_count", 0),
        "exploited": result["exploits_found"],
        "asset_hits": len(alerts),
        "summary": summary,
        "text": brief,
    })

    save_file(brief)

    # ── 完成 ──
    elapsed = (datetime.now() - start_time).total_seconds()
    result["status"] = "success"
    result["finished_at"] = datetime.now().isoformat()
    result["elapsed_seconds"] = round(elapsed, 1)

    logger.info(f"✅ 流水线完成 ({elapsed:.1f}s)")
    logger.info(f"   CVE: {len(cves)} | Exploit: {result['exploits_found']} | 资产命中: {len(alerts)} | 风险: {risk_count}")

    return result


def get_system_status():
    """获取系统整体状态"""
    stats = get_dashboard_stats()
    return {
        "status": "running",
        "database": stats,
        "modules": {
            "crawler": "active",
            "analyzer": "active",
            "exploit_detector": "active",
            "asset_matcher": "active",
            "risk_engine": "active",
            "report": "active",
        },
    }
