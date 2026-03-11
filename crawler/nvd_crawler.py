"""
爬虫模块 - 从 NVD 等来源获取威胁情报（支持分页全量拉取）
"""
import requests
import time
import os
import logging
from datetime import datetime, timedelta
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.getenv("NVD_API_KEY", "")

# NVD 无 API Key 限流：每30秒5次；有 Key：每30秒50次
RATE_LIMIT_DELAY = 0.7 if NVD_API_KEY else 6.5


def _nvd_headers():
    headers = {"User-Agent": "ThreatIntelPlatform/1.0"}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY
    return headers


def fetch_recent_cves(days_back=7, results_per_page=100, max_retries=3):
    """
    从 NVD API 拉取近期 CVE（单页，兼容旧接口）
    """
    pub_start = (datetime.utcnow() - timedelta(days=days_back)).strftime("%Y-%m-%dT%H:%M:%S.000")
    pub_end = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000")

    params = {
        "resultsPerPage": results_per_page,
        "pubStartDate": pub_start,
        "pubEndDate": pub_end,
    }

    for attempt in range(max_retries):
        try:
            logger.info(f"🔍 NVD API 请求 (第 {attempt + 1} 次)...")
            resp = requests.get(NVD_API_BASE, params=params, headers=_nvd_headers(), timeout=30)
            resp.raise_for_status()
            data = resp.json()
            total = data.get("totalResults", 0)
            vulns = data.get("vulnerabilities", [])
            logger.info(f"✅ 获取到 {len(vulns)} 条 CVE（共 {total} 条）")
            return data
        except requests.exceptions.RequestException as e:
            logger.warning(f"⚠️ 请求失败: {e}")
            if attempt < max_retries - 1:
                wait = (attempt + 1) * 6
                logger.info(f"   等待 {wait} 秒后重试...")
                time.sleep(wait)
            else:
                # 429 限流特殊处理
                if resp.status_code == 429:
                    retry_after = int(resp.headers.get("retry-after", 60))
                    logger.info(f"   429 限流，等待 {retry_after} 秒...")
                    time.sleep(retry_after)

    logger.error("❌ NVD API 请求失败，已达最大重试次数")
    return None


def fetch_all_cves(days_back=7, max_total=500):
    """
    分页拉取 NVD CVE（全量，直到拉完或达到上限）

    Returns:
        list[dict]: 原始 NVD vulnerabilities 列表
    """
    pub_start = (datetime.utcnow() - timedelta(days=days_back)).strftime("%Y-%m-%dT%H:%M:%S.000")
    pub_end = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000")

    all_vulns = []
    page = 0
    per_page = 100
    total_results = None

    while True:
        params = {
            "resultsPerPage": per_page,
            "startIndex": page * per_page,
            "pubStartDate": pub_start,
            "pubEndDate": pub_end,
        }

        for attempt in range(3):
            try:
                resp = requests.get(NVD_API_BASE, params=params, headers=_nvd_headers(), timeout=30)
                resp.raise_for_status()
                data = resp.json()
                break
            except requests.exceptions.RequestException as e:
                logger.warning(f"⚠️ 第 {page} 页请求失败 (attempt {attempt + 1}): {e}")
                if attempt < 2:
                    time.sleep((attempt + 1) * 6)
                else:
                    logger.error(f"❌ 第 {page} 页获取失败，停止分页")
                    return all_vulns

        if total_results is None:
            total_results = data.get("totalResults", 0)

        vulns = data.get("vulnerabilities", [])
        all_vulns.extend(vulns)

        logger.info(f"📄 第 {page + 1} 页: 获取 {len(vulns)} 条 | 累计 {len(all_vulns)}/{total_results}")

        # 判断是否还有下一页
        if len(all_vulns) >= total_results or len(all_vulns) >= max_total:
            break

        page += 1
        time.sleep(RATE_LIMIT_DELAY)

    logger.info(f"✅ 分页拉取完成: 共 {len(all_vulns)} 条 CVE")
    return all_vulns


def parse_cve_data(raw_data):
    """
    解析 NVD 原始数据，提取关键字段

    支持两种输入：
    - 完整 API 响应 dict（含 vulnerabilities key）
    - 直接 vulns 列表

    Returns:
        list[dict]: 标准化后的 CVE 列表
    """
    # 兼容列表输入
    if isinstance(raw_data, list):
        vulns = raw_data
    else:
        vulns = raw_data.get("vulnerabilities", [])

    results = []
    for item in vulns:
        cve = item.get("cve", {})
        cve_id = cve.get("id", "UNKNOWN")

        # 描述（取英文）
        descriptions = cve.get("descriptions", [])
        desc_en = next(
            (d["value"] for d in descriptions if d["lang"] == "en"),
            "No description available"
        )

        # CVSS 评分（优先 v3.1 > v3.0）
        metrics = cve.get("metrics", {})
        severity = "UNKNOWN"
        score = 0.0
        cvss_vector = ""
        for key in ("cvssMetricV31", "cvssMetricV30"):
            if key in metrics:
                m = metrics[key][0]["cvssData"]
                severity = m.get("baseSeverity", "UNKNOWN")
                score = m.get("baseScore", 0.0)
                cvss_vector = m.get("vectorString", "")
                break

        # 受影响产品（提取 CPE URI 和简化的产品名）
        affected_cpes = []
        affected_products = []
        for node in cve.get("configurations", []):
            for nd in node.get("nodes", []):
                for cp in nd.get("cpeMatch", []):
                    cpe_uri = cp.get("criteria", "")
                    affected_cpes.append(cpe_uri)
                    # 简化: cpe:2.3:a:apache:http_server:2.4.51:*:*:*:*:*:*:*
                    if cpe_uri.startswith("cpe:2.3:"):
                        parts = cpe_uri.split(":")
                        if len(parts) >= 6:
                            affected_products.append({
                                "vendor": parts[3],
                                "product": parts[4],
                                "version": parts[5],
                                "cpe": cpe_uri,
                            })

        results.append({
            "cve_id": cve_id,
            "description": desc_en,
            "severity": severity,
            "score": score,
            "cvss_vector": cvss_vector,
            "affected_cpes": affected_cpes[:10],
            "affected_products": affected_products[:10],
            "published": cve.get("published", ""),
            "lastModified": cve.get("lastModified", ""),
            "source": "NVD",
        })

    return results
