"""
爬虫模块 - 从 NVD 等来源获取威胁情报
"""
import requests
import time
import os
from dotenv import load_dotenv

load_dotenv()

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.getenv("NVD_API_KEY", "")


def fetch_recent_cves(days_back=7, results_per_page=20, max_retries=3):
    """
    从 NVD API 拉取近期 CVE
    
    Args:
        days_back: 回溯天数
        results_per_page: 每页数量
        max_retries: 最大重试次数
    
    Returns:
        dict: API 返回的漏洞数据，失败返回 None
    """
    headers = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    # 计算起始日期
    from datetime import datetime, timedelta
    pub_start = (datetime.utcnow() - timedelta(days=days_back)).strftime("%Y-%m-%dT00:00:00.000")

    params = {
        "resultsPerPage": results_per_page,
    }

    # 如果指定了回溯天数，使用日期范围查询
    if days_back > 0:
        pub_start = (datetime.utcnow() - timedelta(days=days_back)).strftime("%Y-%m-%dT%H:%M:%S.000")
        pub_end = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000")
        params["pubStartDate"] = pub_start
        params["pubEndDate"] = pub_end

    for attempt in range(max_retries):
        try:
            print(f"🔍 正在请求 NVD API (第 {attempt + 1} 次)...")
            resp = requests.get(NVD_API_BASE, params=params, headers=headers, timeout=30)
            resp.raise_for_status()
            data = resp.json()
            total = data.get("totalResults", 0)
            vulns = data.get("vulnerabilities", [])
            print(f"✅ 获取到 {len(vulns)} 条 CVE（共 {total} 条）")
            return data
        except requests.exceptions.RequestException as e:
            print(f"⚠️ 请求失败: {e}")
            if attempt < max_retries - 1:
                wait = (attempt + 1) * 6  # NVD 限流：6秒递增
                print(f"   等待 {wait} 秒后重试...")
                time.sleep(wait)

    print("❌ NVD API 请求失败，已达最大重试次数")
    return None


def parse_cve_data(raw_data):
    """
    解析 NVD 原始数据，提取关键字段
    
    Returns:
        list[dict]: 标准化后的 CVE 列表
    """
    results = []
    for item in raw_data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id", "UNKNOWN")
        
        # 描述（取英文）
        descriptions = cve.get("descriptions", [])
        desc_en = next(
            (d["value"] for d in descriptions if d["lang"] == "en"),
            "No description available"
        )

        # 严重程度
        metrics = cve.get("metrics", {})
        severity = "UNKNOWN"
        score = 0.0
        if "cvssMetricV31" in metrics:
            m = metrics["cvssMetricV31"][0]["cvssData"]
            severity = m.get("baseSeverity", "UNKNOWN")
            score = m.get("baseScore", 0.0)
        elif "cvssMetricV30" in metrics:
            m = metrics["cvssMetricV30"][0]["cvssData"]
            severity = m.get("baseSeverity", "UNKNOWN")
            score = m.get("baseScore", 0.0)

        # 受影响产品
        affected = []
        for node in cve.get("configurations", []):
            for nd in node.get("nodes", []):
                for cp in nd.get("cpeMatch", []):
                    affected.append(cp.get("criteria", ""))

        results.append({
            "cve_id": cve_id,
            "description": desc_en,
            "severity": severity,
            "score": score,
            "affected_products": affected[:5],  # 最多保存5个
            "published": cve.get("published", ""),
            "lastModified": cve.get("lastModified", ""),
            "source": "NVD",
        })

    return results
