"""
资产匹配模块 - 将 CVE 与本地资产库进行匹配
"""
import json
import os

ASSETS_FILE = os.path.join(os.path.dirname(__file__), "..", "memory", "assets.json")


def load_assets():
    """加载本地资产库"""
    try:
        with open(ASSETS_FILE, "r", encoding="utf-8") as f:
            assets = json.load(f)
        print(f"📦 已加载 {len(assets)} 个资产")
        return assets
    except FileNotFoundError:
        print("⚠️ 未找到资产文件，请创建 memory/assets.json")
        return []
    except json.JSONDecodeError:
        print("⚠️ 资产文件格式错误")
        return []


def save_assets(assets):
    """保存资产库"""
    with open(ASSETS_FILE, "w", encoding="utf-8") as f:
        json.dump(assets, f, ensure_ascii=False, indent=2)
    print(f"💾 已保存 {len(assets)} 个资产")


def add_asset(product, version="unknown"):
    """添加单个资产"""
    assets = load_assets()
    # 检查是否已存在
    for a in assets:
        if a["product"].lower() == product.lower():
            a["version"] = version
            save_assets(assets)
            return {"status": "updated", "product": product, "version": version}
    assets.append({"product": product, "version": version})
    save_assets(assets)
    return {"status": "added", "product": product, "version": version}


def remove_asset(product):
    """删除资产"""
    assets = load_assets()
    new_assets = [a for a in assets if a["product"].lower() != product.lower()]
    if len(new_assets) == len(assets):
        return {"status": "not_found", "product": product}
    save_assets(new_assets)
    return {"status": "removed", "product": product}


def match_assets(cves):
    """
    将 CVE 漏洞与本地资产进行匹配
    同时给每个 CVE 打上 asset_hit 标记
    """
    assets = load_assets()
    if not assets:
        # 无资产，标记所有 CVE 为未命中
        for cve in cves:
            cve["asset_hit"] = False
        return []

    alerts = []
    asset_product_names = [a["product"].lower() for a in assets]

    for cve in cves:
        desc = cve.get("description", "").lower()
        affected = [p.lower() for p in cve.get("affected_products", [])]

        matched_product = None
        for asset in assets:
            product = asset["product"].lower()
            if product in desc or any(product in a for a in affected):
                matched_product = asset
                break

        if matched_product:
            cve["asset_hit"] = True
            alerts.append({
                "cve_id": cve["cve_id"],
                "product": matched_product["product"],
                "version": matched_product.get("version", "unknown"),
                "severity": cve.get("severity", "unknown"),
                "score": cve.get("score", 0),
                "description": cve.get("description", "")[:100],
                "exploit": cve.get("exploit", {}),
            })
        else:
            cve["asset_hit"] = False

    return alerts


def format_asset_alerts(alerts):
    """格式化资产告警为可读文本"""
    if not alerts:
        return "✅ 未发现影响资产的漏洞"

    lines = ["🚨 资产受影响漏洞告警", "=" * 50]
    for alert in alerts:
        exploit_tag = ""
        if isinstance(alert.get("exploit"), dict) and alert["exploit"].get("has_exploit"):
            exploit_tag = " 🔥已存在利用代码"

        lines.append(
            f"  {alert['cve_id']}  |  "
            f"{alert['product']} {alert['version']}  |  "
            f"[{alert['severity']}] CVSS {alert['score']}"
            f"{exploit_tag}"
        )
        lines.append(f"    {alert['description']}")

    lines.append("=" * 50)
    lines.append(f"共 {len(alerts)} 个漏洞影响你的资产")
    return "\n".join(lines)
