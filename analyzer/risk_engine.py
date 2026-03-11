"""
风险引擎 - 综合评估漏洞风险等级（升级版）
"""
from datetime import datetime


def calculate_risk_score(cve):
    """
    综合计算漏洞风险分（0-100）

    考虑因素：
    - CVSS 基础分 (0-30)
    - 严重程度 (0-20)
    - Exploit 状态 (0-25)
    - 资产匹配 (0-15)
    - 时效性 (0-10)
    """
    score = 0

    # 1. CVSS 贡献（0-30分）
    cvss = cve.get("score", 0)
    score += min(cvss / 10.0 * 30, 30)

    # 2. 严重程度贡献（0-20分）
    severity_map = {"CRITICAL": 20, "HIGH": 15, "MEDIUM": 8, "LOW": 4, "UNKNOWN": 2}
    severity = cve.get("severity", "UNKNOWN").upper()
    score += severity_map.get(severity, 2)

    # 3. Exploit 贡献（0-25分）— 有 exploit 风险翻倍
    exploit_info = cve.get("exploit", {})
    has_exploit = False
    if isinstance(exploit_info, dict):
        has_exploit = exploit_info.get("has_exploit", False)
    elif isinstance(exploit_info, bool):
        has_exploit = exploit_info

    if has_exploit:
        source = exploit_info.get("source", "") if isinstance(exploit_info, dict) else ""
        if "CISA" in source:
            score += 25  # 已在野利用 — 最高权重
        else:
            score += 18  # 公开 exploit — 高权重

    # 4. 资产匹配贡献（0-15分）
    asset_hit = cve.get("asset_hit", False)
    if asset_hit:
        score += 15

    # 5. 时效性贡献（0-10分）
    published = cve.get("published", "")
    if published:
        try:
            pub_time = datetime.fromisoformat(published.replace("Z", "+00:00"))
            age_days = (datetime.now(pub_time.tzinfo) - pub_time).days
            if age_days <= 7:
                score += 10
            elif age_days <= 30:
                score += 7
            elif age_days <= 90:
                score += 4
            else:
                score += 1
        except (ValueError, TypeError):
            score += 2

    return round(min(score, 100), 1)


def assign_risk_level(risk_score):
    """根据风险分分配等级"""
    if risk_score >= 80:
        return "CRITICAL"
    elif risk_score >= 60:
        return "HIGH"
    elif risk_score >= 40:
        return "MEDIUM"
    elif risk_score >= 20:
        return "LOW"
    return "INFO"


def rank_cves(cves, top_n=10):
    """对漏洞按风险分排序，附带 exploit 和资产信息"""
    ranked = []
    for cve in cves:
        risk_score = calculate_risk_score(cve)
        ranked.append({
            **cve,
            "risk_score": risk_score,
            "risk_level": assign_risk_level(risk_score),
        })

    ranked.sort(key=lambda x: x["risk_score"], reverse=True)
    return ranked[:top_n]


def generate_risk_report(ranked_cves):
    """生成风险报告"""
    if not ranked_cves:
        return "暂无数据"

    lines = ["🏆 漏洞风险排行榜", "=" * 60]

    for i, cve in enumerate(ranked_cves, 1):
        exploit_status = ""
        exploit_info = cve.get("exploit", {})
        if isinstance(exploit_info, dict) and exploit_info.get("has_exploit"):
            exploit_status = f" 🔥{exploit_info.get('source', 'EXPLOIT')}"

        asset_tag = " 🎯资产" if cve.get("asset_hit") else ""

        lines.append(
            f"\n  #{i}  {cve['cve_id']}  "
            f"[{cve['risk_level']}]  "
            f"风险分: {cve['risk_score']}"
            f"{exploit_status}{asset_tag}"
        )
        lines.append(
            f"       CVSS {cve['score']}  [{cve['severity']}]"
        )

    lines.append("\n" + "=" * 60)
    return "\n".join(lines)
