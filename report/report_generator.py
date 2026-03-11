"""
报告模块 - 生成企业安全情报简报
"""
import json
from datetime import datetime


def generate_daily_brief(summary, alerts, ranked_cves):
    """生成每日安全情报简报"""
    now = datetime.now()
    lines = [
        "═" * 60,
        "       🛡️  企业安全情报日报",
        f"       {now.strftime('%Y-%m-%d %A')}",
        "═" * 60,
        "",
        "📊 情报概览",
        "-" * 40,
        f"  今日新增漏洞:  {summary.get('total', 0)}",
        f"  高危漏洞:      {summary.get('high_risk_count', 0)}",
        f"  影响企业资产:  {len(alerts)}",
    ]

    # 严重程度分布
    dist = summary.get("severity_distribution", {})
    if dist:
        lines.append("")
        lines.append("📈 严重程度分布")
        for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            count = dist.get(level, 0)
            if count > 0:
                bar = "█" * min(count, 30)
                lines.append(f"  {level:10s} {bar} {count}")

    # 资产受影响漏洞
    if alerts:
        lines.append("")
        lines.append("🎯 影响企业资产漏洞")
        lines.append("-" * 40)
        for alert in alerts:
            exploit_tag = ""
            if isinstance(alert.get("exploit"), dict) and alert["exploit"].get("has_exploit"):
                source = alert["exploit"].get("source", "EXPLOIT")
                exploit_tag = f"  ⚠️ 已存在{source}利用代码"
            lines.append(
                f"  • {alert['cve_id']}  "
                f"{alert['product']} {alert['version']}"
            )
            lines.append(
                f"    风险: [{alert['severity']}] CVSS {alert['score']}"
                f"{exploit_tag}"
            )
    else:
        lines.append("")
        lines.append("✅ 当前无漏洞影响企业资产")

    # 风险排行榜
    if ranked_cves:
        lines.append("")
        lines.append("🏆 漏洞风险 TOP10")
        lines.append("-" * 40)
        for i, cve in enumerate(ranked_cves, 1):
            exploit_flag = " 🔥" if (
                isinstance(cve.get("exploit"), dict)
                and cve["exploit"].get("has_exploit")
            ) else ""
            asset_flag = " 🎯" if cve.get("asset_hit") else ""
            lines.append(
                f"  {i:2d}. {cve['cve_id']}  "
                f"[{cve['risk_level']:8s}]  "
                f"风险分:{cve['risk_score']:5.1f}"
                f"{exploit_flag}{asset_flag}"
            )

    # 受影响最多的产品
    top_products = summary.get("top_vulnerable_products", [])
    if top_products:
        lines.append("")
        lines.append("🏭 受影响最多的产品")
        lines.append("-" * 40)
        for product, count in top_products[:5]:
            lines.append(f"  {product}: {count} 个漏洞")

    lines.append("")
    lines.append("═" * 60)
    lines.append(f"报告生成时间: {now.strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("═" * 60)

    return "\n".join(lines)


def generate_json_report(summary, alerts=None, ranked_cves=None):
    """生成 JSON 格式报告"""
    return json.dumps({
        "summary": summary,
        "asset_alerts": alerts or [],
        "risk_ranking": ranked_cves or [],
        "generated_at": datetime.now().isoformat(),
    }, ensure_ascii=False, indent=2)


def save_report(report_text, filepath=None):
    """保存报告到文件"""
    if filepath is None:
        filepath = f"memory/brief_{datetime.now().strftime('%Y%m%d')}.txt"
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(report_text)
    print(f"📄 报告已保存: {filepath}")
    return filepath
