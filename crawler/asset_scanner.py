"""
资产自动发现模块 - 扫描主机并识别软件/服务

支持：
- 端口扫描识别服务
- HTTP Banner 抓取
- 主机资产导入
"""
import socket
import subprocess
import re
import json
import os
from datetime import datetime
from database.db_manager import add_asset_to_db, get_all_assets

ASSETS_FILE = os.path.join(os.path.dirname(__file__), "..", "memory", "assets.json")

# 常见端口 → 服务/产品映射
PORT_SERVICE_MAP = {
    21: ("FTP", "unknown"),
    22: ("OpenSSH", "unknown"),
    23: ("Telnet", "unknown"),
    25: ("Postfix", "unknown"),
    53: ("BIND", "unknown"),
    80: ("Apache/Nginx", "unknown"),
    110: ("Dovecot", "unknown"),
    143: ("IMAP", "unknown"),
    443: ("Apache/Nginx", "unknown"),
    445: ("SMB", "unknown"),
    993: ("IMAPS", "unknown"),
    995: ("POP3S", "unknown"),
    1433: ("MSSQL", "unknown"),
    1521: ("Oracle", "unknown"),
    3306: ("MySQL", "unknown"),
    3389: ("RDP", "unknown"),
    5432: ("PostgreSQL", "unknown"),
    5900: ("VNC", "unknown"),
    6379: ("Redis", "unknown"),
    8080: ("Tomcat/Nginx", "unknown"),
    8443: ("Tomcat", "unknown"),
    9200: ("Elasticsearch", "unknown"),
    27017: ("MongoDB", "unknown"),
}


def scan_ports(host, ports=None, timeout=1):
    """
    扫描目标主机开放端口

    Args:
        host: 目标 IP 或主机名
        ports: 端口列表（None 则扫描常见端口）
        timeout: 超时秒数

    Returns:
        list[dict]: 开放端口信息
    """
    if ports is None:
        ports = sorted(PORT_SERVICE_MAP.keys())

    open_ports = []
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            if result == 0:
                service, version = PORT_SERVICE_MAP.get(port, ("unknown", "unknown"))
                open_ports.append({
                    "host": host,
                    "port": port,
                    "service": service,
                    "version": version,
                    "state": "open",
                })
            sock.close()
        except (socket.timeout, socket.error, OSError):
            continue

    return open_ports


def grab_http_banner(host, port=80, timeout=5):
    """
    抓取 HTTP 服务 Banner

    Returns:
        dict: 包含 server, 软件版本等信息
    """
    result = {"host": host, "port": port, "banner": "", "products": []}

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.send(f"HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
        data = sock.recv(4096).decode("utf-8", errors="ignore")
        sock.close()

        # 提取 Server 头
        server_match = re.search(r"Server:\s*(.+?)\r?\n", data, re.IGNORECASE)
        if server_match:
            result["banner"] = server_match.group(1).strip()
            # 解析产品版本
            result["products"] = _parse_server_banner(result["banner"])

    except (socket.timeout, socket.error, OSError):
        pass

    return result


def _parse_server_banner(banner):
    """从 Server header 解析产品版本"""
    products = []
    # 常见模式
    patterns = [
        (r"Apache/([\d.]+)", "Apache"),
        (r"nginx/([\d.]+)", "Nginx"),
        (r"OpenSSH_([\d.]+)", "OpenSSH"),
        (r"OpenSSL/([\d.]+)", "OpenSSL"),
        (r"Microsoft-IIS/([\d.]+)", "IIS"),
        (r"Tomcat/([\d.]+)", "Tomcat"),
        (r"Redis/([\d.]+)", "Redis"),
        (r"MySQL/([\d.]+)", "MySQL"),
        (r"PostgreSQL/([\d.]+)", "PostgreSQL"),
        (r"MongoDB/([\d.]+)", "MongoDB"),
        (r"Elasticsearch/([\d.]+)", "Elasticsearch"),
        (r"Envoy/([\d.]+)", "Envoy"),
    ]
    for pattern, product in patterns:
        match = re.search(pattern, banner, re.IGNORECASE)
        if match:
            products.append({"product": product, "version": match.group(1)})

    if not products and banner:
        products.append({"product": banner.split("/")[0], "version": banner.split("/")[-1] if "/" in banner else "unknown"})

    return products


def scan_host(host, scan_web=True, timeout=1):
    """
    综合扫描一个主机

    Args:
        host: IP 地址
        scan_web: 是否抓取 Web Banner
        timeout: 端口扫描超时

    Returns:
        dict: 扫描结果
    """
    print(f"🔍 扫描主机: {host}")

    # 端口扫描
    ports = scan_ports(host, timeout=timeout)
    print(f"   发现 {len(ports)} 个开放端口")

    # HTTP Banner
    web_info = {}
    web_ports = [p for p in ports if p["port"] in (80, 443, 8080, 8443, 8000)]
    if scan_web and web_ports:
        port = web_ports[0]["port"]
        web_info = grab_http_banner(host, port)
        if web_info["products"]:
            print(f"   识别到服务: {web_info['products']}")

    # 合并结果为资产列表
    discovered_assets = []
    for p in ports:
        discovered_assets.append({
            "product": p["service"],
            "version": p["version"],
            "host": host,
            "port": p["port"],
            "source": "port_scan",
        })

    for product_info in web_info.get("products", []):
        # 如果 web banner 有更详细的信息，更新端口扫描的结果
        for asset in discovered_assets:
            if asset["product"].lower() in product_info["product"].lower():
                asset["version"] = product_info["version"]
                asset["source"] = "banner"
                break
        else:
            discovered_assets.append({
                "product": product_info["product"],
                "version": product_info["version"],
                "host": host,
                "port": web_ports[0]["port"] if web_ports else 0,
                "source": "banner",
            })

    return {
        "host": host,
        "timestamp": datetime.now().isoformat(),
        "open_ports": len(ports),
        "web_banner": web_info,
        "discovered_assets": discovered_assets,
    }


def import_scan_results(scan_results, auto_register=True):
    """
    将扫描结果导入为资产

    Args:
        scan_results: scan_host 返回的结果列表
        auto_register: 是否自动注册到数据库

    Returns:
        dict: 导入统计
    """
    all_assets = []
    for result in scan_results:
        all_assets.extend(result.get("discovered_assets", []))

    # 去重
    seen = set()
    unique_assets = []
    for a in all_assets:
        key = (a["product"].lower(), a.get("version", "unknown"))
        if key not in seen:
            seen.add(key)
            unique_assets.append(a)

    registered = 0
    if auto_register:
        for a in unique_assets:
            add_asset_to_db(
                product=a["product"],
                version=a.get("version", "unknown"),
                host=a.get("host", ""),
            )
            registered += 1

    return {
        "total_discovered": len(all_assets),
        "unique_products": len(unique_assets),
        "registered": registered,
        "assets": unique_assets,
    }


def scan_and_import(hosts, timeout=1):
    """
    批量扫描主机并导入资产

    Args:
        hosts: 主机列表（IP 或域名）
        timeout: 扫描超时

    Returns:
        dict: 批量扫描结果
    """
    print(f"\n{'='*60}")
    print(f"🔍 资产自动发现 | 目标: {len(hosts)} 台主机")
    print(f"{'='*60}")

    all_results = []
    for host in hosts:
        result = scan_host(host, timeout=timeout)
        all_results.append(result)

    import_result = import_scan_results(all_results)
    print(f"\n✅ 扫描完成:")
    print(f"   扫描主机: {len(hosts)}")
    print(f"   发现产品: {import_result['unique_products']}")
    print(f"   已注册:   {import_result['registered']}")

    return import_result
