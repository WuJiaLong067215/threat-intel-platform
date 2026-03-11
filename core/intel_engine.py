"""
情报引擎 - 核心编排层

统一编排：采集 → 分析 → Exploit → 资产匹配 → 风险评分 → 存储 → 报告
"""
from datetime import datetime
from crawler.nvd_crawler import fetch_recent_cves, parse_cve_data
from analyzer.vuln_analyzer import generate_summary
from analyzer.exploit_detector import batch_check_exploits
from analyzer.asset_matcher import match_assets, load_assets
from analyzer.risk_engine import rank_cves
from report.report_generator import generate_daily_brief, save_report as save_file
from database.db_manager import (
    upsert_cves, upsert_risks, save_report_to_db,
    find_cves, get_dashboard_stats,
)


def run_full_pipeline(days_back=7, check_exploit_flag=True, limit=20):
    """
    执行完整的情报流水线

    Args:
        days_back: 回溯天数
        check_exploit_flag: 是否检测 Exploit
        limit: 每次采集数量

    Returns:
        dict: 流水线执行结果
    """
    start_time = datetime.now()
    print(f"\n{'='*60}")
    print(f"🔄 情报引擎启动 | {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}")

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

    # ── Step 1: 采集 ──
    print("\n📡 Step 1: 采集 CVE 情报...")
    raw = fetch_recent_cves(days_back=days_back, results_per_page=limit)
    if not raw:
        result["status"] = "failed"
        result["errors"].append("NVD API 采集失败")
        result["finished_at"] = datetime.now().isoformat()
        return result

    cves = parse_cve_data(raw)
    result["cves_collected"] = len(cves)
    print(f"   获取 {len(cves)} 条 CVE")

    # ── Step 2: Exploit 检测 ──
    if check_exploit_flag:
        print("\n🔥 Step 2: Exploit 检测...")
        cves = batch_check_exploits(cves, max_workers=3, delay=1.0)
        result["exploits_checked"] = sum(
            1 for c in cves
            if isinstance(c.get("exploit"), dict) and c["exploit"].get("has_exploit")
        )
        result["exploits_found"] = result["exploits_checked"]
    else:
        # 无 exploit 检测时补默认值
        for c in cves:
            c.setdefault("exploit", {"has_exploit": False, "source": None, "details": "未检测"})

    # ── Step 3: 资产匹配 ──
    print("\n🎯 Step 3: 资产匹配...")
    alerts = match_assets(cves)
    result["asset_hits"] = len(alerts)

    # ── Step 4: 风险评分 ──
    print("\n⚡ Step 4: 风险评分...")
    ranked = rank_cves(cves, top_n=50)

    # ── Step 5: 生成报告 ──
    print("\n📊 Step 5: 生成简报...")
    summary = generate_summary(cves)
    brief = generate_daily_brief(summary, alerts, ranked)
    print(brief)

    # ── Step 6: 写入数据库 ──
    print("\n💾 Step 6: 写入数据库...")
    cve_count = upsert_cves(cves)

    # 写入风险关联
    risk_records = []
    for alert in alerts:
        risk_records.append({
            "cve_id": alert["cve_id"],
            "product": alert["product"],
            "version": alert.get("version", "unknown"),
            "severity": alert.get("severity", "unknown"),
            "score": alert.get("score", 0),
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

    # 保存报告到数据库
    save_report_to_db({
        "date": datetime.now().strftime("%Y-%m-%d"),
        "total_cves": len(cves),
        "high_risk": summary.get("high_risk_count", 0),
        "exploited": result["exploits_found"],
        "asset_hits": len(alerts),
        "summary": summary,
        "text": brief,
    })

    # 保存报告文件
    save_file(brief)

    # ── 完成 ──
    elapsed = (datetime.now() - start_time).total_seconds()
    result["status"] = "success"
    result["finished_at"] = datetime.now().isoformat()
    result["elapsed_seconds"] = round(elapsed, 1)

    print(f"\n✅ 流水线完成 ({elapsed:.1f}s)")
    print(f"   CVE: {len(cves)} | Exploit: {result['exploits_found']} | 资产命中: {len(alerts)} | 风险: {risk_count}")

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
