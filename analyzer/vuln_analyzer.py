"""
分析模块 - 漏洞分析与评估
"""
from datetime import datetime, timedelta


def severity_distribution(cves):
    """统计漏洞严重程度分布"""
    dist = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    for cve in cves:
        s = cve.get("severity", "UNKNOWN").upper()
        dist[s] = dist.get(s, 0) + 1
    return dist


def top_vulnerable_products(cves, top_n=10):
    """统计受影响最多的产品"""
    product_count = {}
    for cve in cves:
        for product in cve.get("affected_products", []):
            # 简化产品名（取最后两段）
            parts = product.split(":")
            if len(parts) >= 3:
                key = ":".join(parts[-3:-1])
            else:
                key = product
            product_count[key] = product_count.get(key, 0) + 1

    sorted_products = sorted(product_count.items(), key=lambda x: x[1], reverse=True)
    return sorted_products[:top_n]


def is_high_risk(cve):
    """判断是否为高危漏洞（CVSS >= 7.0 或 CRITICAL）"""
    score = cve.get("score", 0)
    severity = cve.get("severity", "").upper()
    return score >= 7.0 or severity == "CRITICAL"


def filter_high_risk(cves):
    """过滤出高危漏洞"""
    return [cve for cve in cves if is_high_risk(cve)]


def generate_summary(cves):
    """生成情报摘要"""
    if not cves:
        return {"message": "暂无漏洞数据"}

    high_risk = filter_high_risk(cves)
    dist = severity_distribution(cves)
    top_products = top_vulnerable_products(cves, 5)

    return {
        "total": len(cves),
        "high_risk_count": len(high_risk),
        "severity_distribution": dist,
        "top_vulnerable_products": top_products,
        "latest_high_risk": [
            {"cve_id": c["cve_id"], "severity": c["severity"], "score": c["score"]}
            for c in high_risk[:5]
        ],
        "generated_at": datetime.now().isoformat(),
    }
