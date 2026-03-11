"""
CNVD 爬虫 - 国家信息安全漏洞共享平台

数据源：https://www.cnvd.org.cn
解析公开漏洞信息，转为统一 CVE 格式
"""
import re
import logging
import time
from datetime import datetime, timedelta

import requests
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

CNVD_BASE = "https://www.cnvd.org.cn"
CNVD_LIST_URL = f"{CNVD_BASE}/flaw/list.htm"
CNVD_DETAIL_URL = f"{CNVD_BASE}/flaw/show/"


def fetch_cnvd_list(days_back=7, max_pages=3):
    """
    获取 CNVD 近期漏洞列表

    Returns:
        list[dict]: CNVD 漏洞列表
    """
    results = []
    end_date = datetime.now().strftime("%Y-%m-%d")
    start_date = (datetime.now() - timedelta(days=days_back)).strftime("%Y-%m-%d")

    headers = {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
    }

    for page in range(1, max_pages + 1):
        try:
            params = {
                "number": "",
                "startDate": start_date,
                "endDate": end_date,
                "flag": "true",
                "numPerPage": "20",
                "offset": str((page - 1) * 20),
            }
            resp = requests.get(CNVD_LIST_URL, params=params, headers=headers, timeout=15)
            resp.raise_for_status()
            resp.encoding = "utf-8"

            soup = BeautifulSoup(resp.text, "html.parser")
            table = soup.find("table", {"class": "t_list"})
            if not table:
                logger.warning(f"CNVD 第 {page} 页解析失败")
                break

            rows = table.find_all("tr")[1:]  # 跳过表头
            page_count = 0

            for row in rows:
                tds = row.find_all("td")
                if len(tds) < 5:
                    continue

                cnvd_id = tds[0].get_text(strip=True)
                title = tds[1].get_text(strip=True)
                hazard_level = tds[2].get_text(strip=True)
                product = tds[3].get_text(strip=True) if len(tds) > 3 else ""
                pub_date = tds[4].get_text(strip=True) if len(tds) > 4 else ""

                # 提取关联 CVE ID
                cve_ids = re.findall(r"CVE-\d{4}-\d+", title)

                # 威胁等级映射
                severity_map = {"超危": "CRITICAL", "高危": "HIGH", "中危": "MEDIUM", "低危": "LOW"}
                severity = severity_map.get(hazard_level, "UNKNOWN")

                # CNVD 特有评分（简化映射）
                score_map = {"超危": 9.5, "高危": 7.5, "中危": 5.0, "低危": 2.5}
                score = score_map.get(hazard_level, 0.0)

                results.append({
                    "cve_id": cve_ids[0] if cve_ids else f"CNVD-{cnvd_id}",
                    "cnvd_id": cnvd_id,
                    "title": title,
                    "description": title,
                    "severity": severity,
                    "score": score,
                    "affected_products": [{"vendor": "", "product": product, "version": "", "cpe": ""}],
                    "affected_cpes": [],
                    "published": pub_date,
                    "lastModified": pub_date,
                    "source": "CNVD",
                    "cvss_vector": "",
                    "is_cnvd_only": len(cve_ids) == 0,  # 标记为 CNVD 独有漏洞
                    "original_hazard_level": hazard_level,
                })
                page_count += 1

            logger.info(f"📄 CNVD 第 {page} 页: {page_count} 条漏洞")
            if page_count == 0:
                break

            time.sleep(2)  # 礼貌延迟

        except Exception as e:
            logger.error(f"CNVD 第 {page} 页获取失败: {e}")
            break

    logger.info(f"✅ CNVD 共获取 {len(results)} 条漏洞")
    return results


def fetch_cnvd_detail(cnvd_id: str):
    """
    获取 CNVD 漏洞详情

    Returns:
        dict: 漏洞详情
    """
    headers = {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
    }
    try:
        resp = requests.get(f"{CNVD_DETAIL_URL}{cnvd_id}", headers=headers, timeout=15)
        resp.encoding = "utf-8"
        soup = BeautifulSoup(resp.text, "html.parser")

        detail_div = soup.find("div", {"class": "blkContainerSblkL"})
        if not detail_div:
            return None

        # 提取详细描述
        desc_div = detail_div.find("div", {"class": "blkUnit"})
        description = desc_div.get_text(strip=True) if desc_div else ""

        # 提取补丁信息
        patches = []
        for link in detail_div.find_all("a", href=True):
            href = link["href"]
            if href and ("patch" in href.lower() or "download" in href.lower()):
                patches.append({"name": link.get_text(strip=True), "url": href})

        return {
            "cnvd_id": cnvd_id,
            "description": description[:500],
            "patches": patches,
            "fetched_at": datetime.now().isoformat(),
        }
    except Exception as e:
        logger.error(f"CNVD 详情获取失败 {cnvd_id}: {e}")
        return None
