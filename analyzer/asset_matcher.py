"""
资产匹配模块 - 将 CVE 与本地资产库进行精确匹配（CPE + 关键词混合）

匹配策略（优先级从高到低）：
1. CPE 精确匹配：vendor + product + version 完全一致
2. CPE 产品匹配：vendor + product 一致，版本范围覆盖
3. 关键词匹配：产品名在描述/受影响产品中出现
"""
import re
from database.db_manager import load_assets, add_asset_to_db, remove_asset_from_db, get_all_assets


def add_asset(product, version="unknown"):
    """添加单个资产"""
    add_asset_to_db(product=product, version=version)
    return {"status": "added", "product": product, "version": version}


def remove_asset(product):
    """删除资产"""
    result = remove_asset_from_db(product)
    if result:
        return {"status": "removed", "product": product}
    return {"status": "not_found", "product": product}


def _normalize_product_name(name):
    """标准化产品名：小写、去空格、统一常见变体"""
    n = name.lower().strip()
    # 常见变体映射
    mapping = {
        "apache http server": "apache",
        "apache httpd": "apache",
        "httpd": "apache",
        "apache tomcat": "tomcat",
        "nginx": "nginx",
        "open ssh": "openssh",
        "openssh": "openssh",
        "microsoft windows": "windows",
        "windows server": "windows server",
        "linux kernel": "linux",
        "openssl": "openssl",
        "vmware": "vmware",
    }
    return mapping.get(n, n)


def _version_match(asset_version, cpe_version):
    """
    检查资产版本是否在 CVE 影响范围内

    NVD CPE 中的版本可能是：
    - 精确版本: "2.4.51"
    - 通配符:   "*" (所有版本)
    - 范围前缀: "2.4" (2.4.x 全部)
    """
    asset_v = str(asset_version).lower().strip()
    cpe_v = str(cpe_version).lower().strip()

    if cpe_v == "*" or cpe_v == "-":
        return True
    if asset_v in ("unknown", "", "-"):
        return False

    # 精确匹配
    if asset_v == cpe_v:
        return True

    # 前缀匹配：cpe 版本是 "2.4"，资产版本是 "2.4.51"
    if asset_v.startswith(cpe_v + "."):
        return True
    if cpe_v.startswith(asset_v + "."):
        return True

    return False


def match_assets(cves):
    """
    将 CVE 漏洞与本地资产进行匹配

    三层匹配策略：
    1. CPE 精确匹配（vendor:product:version）
    2. CPE 产品匹配（vendor:product，版本覆盖）
    3. 关键词降级匹配（产品名出现在描述中）
    """
    assets = load_assets()
    if not assets:
        for cve in cves:
            cve["asset_hit"] = False
        return []

    # 预处理资产：标准化名称
    normalized_assets = []
    for a in assets:
        normalized_assets.append({
            **a,
            "_normalized": _normalize_product_name(a.get("product", "")),
        })

    alerts = []

    for cve in cves:
        matched = False
        matched_product = None
        matched_method = None

        # 受影响产品列表（从 CPE 解析出的结构化数据）
        cpe_products = cve.get("affected_products", [])
        # 兼容旧格式（字符串列表）
        cpe_strings = cve.get("affected_cpes", [])
        desc = cve.get("description", "").lower()

        for asset in normalized_assets:
            asset_norm = asset["_normalized"]
            asset_ver = str(asset.get("version", "unknown")).lower()

            # ── 策略 1: CPE 精确匹配 ──
            if not matched and cpe_products:
                for cp in cpe_products:
                    cp_vendor = cp.get("vendor", "").lower()
                    cp_product = cp.get("product", "").lower()
                    cp_version = cp.get("version", "")

                    if (asset_norm == _normalize_product_name(cp_product)
                            and _version_match(asset_ver, cp_version)):
                        matched = True
                        matched_product = asset
                        matched_method = "cpe_exact"
                        break

            # ── 策略 2: CPE 产品匹配（只看产品名，版本覆盖） ──
            if not matched and cpe_products:
                for cp in cpe_products:
                    cp_product = cp.get("product", "").lower()
                    cp_version = cp.get("version", "")

                    if (asset_norm == _normalize_product_name(cp_product)
                            and cp_version in ("*", "-", "")):
                        # 版本通配，说明所有版本受影响
                        matched = True
                        matched_product = asset
                        matched_method = "cpe_wildcard"
                        break

                    if (asset_norm == _normalize_product_name(cp_product)
                            and _version_match(asset_ver, cp_version)):
                        matched = True
                        matched_product = asset
                        matched_method = "cpe_version"
                        break

            # ── 策略 3: 关键词降级匹配 ──
            if not matched:
                keywords = [asset_norm]
                # 常见品牌别名
                aliases = {
                    "apache": ["apache http", "httpd"],
                    "nginx": ["nginx"],
                    "openssl": ["openssl", "libssl"],
                    "vmware": ["vmware", "vcenter", "esxi"],
                    "windows server": ["windows server", "microsoft windows server"],
                }
                keywords.extend(aliases.get(asset_norm, []))

                for kw in keywords:
                    if kw in desc:
                        matched = True
                        matched_product = asset
                        matched_method = "keyword"
                        break

            if matched:
                break

        cve["asset_hit"] = matched
        if matched and matched_product:
            alerts.append({
                "cve_id": cve["cve_id"],
                "product": matched_product["product"],
                "version": matched_product.get("version", "unknown"),
                "severity": cve.get("severity", "unknown"),
                "score": cve.get("score", 0),
                "description": cve.get("description", "")[:200],
                "match_method": matched_method,
                "exploit": cve.get("exploit", {}),
            })

    return alerts


def format_asset_alerts(alerts):
    """格式化资产告警为可读文本"""
    if not alerts:
        return "✅ 未发现影响资产的漏洞"

    lines = ["🚨 资产受影响漏洞告警", "=" * 50]
    for alert in alerts:
        exploit_tag = ""
        if isinstance(alert.get("exploit"), dict) and alert["exploit"].get("has_exploit"):
            source = alert["exploit"].get("source", "EXPLOIT")
            exploit_tag = f"  ⚠️ 已存在{source}利用代码"

        method_tag = f" [{alert.get('match_method', 'unknown')}匹配]"

        lines.append(
            f"  {alert['cve_id']}  |  "
            f"{alert['product']} {alert['version']}  |  "
            f"[{alert['severity']}] CVSS {alert['score']}"
            f"{method_tag}{exploit_tag}"
        )
        lines.append(f"    {alert['description']}")

    lines.append("=" * 50)
    lines.append(f"共 {len(alerts)} 个漏洞影响你的资产")
    return "\n".join(lines)
