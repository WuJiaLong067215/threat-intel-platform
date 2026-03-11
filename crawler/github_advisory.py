"""
GitHub Advisory 爬虫 - 从 GitHub Security Advisories 获取漏洞情报

利用 GitHub 的 GraphQL API（公开无需认证）获取安全公告
"""
import re
import logging
from datetime import datetime, timedelta

import requests

logger = logging.getLogger(__name__)

GITHUB_GRAPHQL_URL = "https://api.github.com/graphql"


# 安全公告的 severity 映射
GH_SEVERITY_MAP = {
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MODERATE": "MEDIUM",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
    "UNKNOWN": "UNKNOWN",
}


def fetch_github_advisories(days_back=30, max_results=50):
    """
    获取 GitHub 最近的公开安全公告

    Returns:
        list[dict]: 标准化后的漏洞列表
    """
    headers = {
        "User-Agent": "ThreatIntelPlatform/1.0",
    }

    # 使用 REST API（更简单，无需 GraphQL）
    url = "https://api.github.com/advisories"
    params = {
        "per_page": 100,
        "sort": "published",
        "direction": "desc",
    }

    try:
        resp = requests.get(url, params=params, headers=headers, timeout=15)
        resp.raise_for_status()
        advisories = resp.json()

    except Exception as e:
        logger.error(f"GitHub Advisory 获取失败: {e}")
        return []

    # 过滤最近 N 天的
    cutoff = (datetime.utcnow() - timedelta(days=days_back)).isoformat() + "Z"
    results = []

    for adv in advisories[:max_results]:
        pub_date = adv.get("published_at", "")
        if pub_date < cutoff:
            continue

        # 提取 CVE ID
        cve_id = adv.get("cve_id", "")
        if not cve_id:
            # 使用 GHSA ID
            cve_id = adv.get("ghsa_id", f"GHSA-{adv.get('id', 'unknown')}")

        # Severity
        severity = GH_SEVERITY_MAP.get(adv.get("severity", "UNKNOWN").upper(), "UNKNOWN")

        # Score（GitHub Advisory 提供了 CVSS 分数）
        cvss = adv.get("cvss", {})
        score = 0.0
        if cvss:
            score = cvss.get("score", 0.0) or cvss.get("base_score", 0.0)

        # 受影响包
        vuln_package = adv.get("vulnerability_package", {})
        ecosystem = vuln_package.get("ecosystem", "")
        pkg_name = vuln_package.get("name", "")

        affected_products = []
        if pkg_name:
            affected_products.append({
                "vendor": ecosystem,
                "product": pkg_name,
                "version": adv.get("vulnerable_version_range", ""),
                "cpe": "",
            })

        # 提取描述中的关联 CVE
        description = adv.get("description", "")
        summary = adv.get("summary", description[:200])

        results.append({
            "cve_id": cve_id,
            "ghsa_id": adv.get("ghsa_id", ""),
            "title": summary,
            "description": description[:500],
            "severity": severity,
            "score": float(score) if score else _severity_to_score(severity),
            "affected_products": affected_products,
            "affected_cpes": [],
            "published": pub_date,
            "lastModified": adv.get("updated_at", pub_date),
            "source": "GitHub Advisory",
            "cvss_vector": cvss.get("vector_string", "") if cvss else "",
            "is_ghsa_only": not bool(adv.get("cve_id")),
            "ecosystem": ecosystem,
            "patched_versions": adv.get("patched_versions", ""),
            "first_patched_version": adv.get("first_patched_version", {}),
        })

    logger.info(f"✅ GitHub Advisory 获取 {len(results)} 条安全公告")
    return results


def _severity_to_score(severity: str) -> float:
    """根据 severity 名称估算分数"""
    return {
        "CRITICAL": 9.5,
        "HIGH": 7.5,
        "MEDIUM": 5.0,
        "LOW": 2.5,
    }.get(severity, 0.0)
