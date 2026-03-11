"""
资产批量导入 - 支持 CSV / Excel 批量导入资产
"""
import csv
import io
import logging
from datetime import datetime

logger = logging.getLogger(__name__)


def parse_csv(content: str, delimiter: str = ",") -> list[dict]:
    """
    解析 CSV 内容为资产列表

    CSV 格式要求：
    product,version,host,department
    Apache,2.4,192.168.1.10,IT部
    Nginx,1.24,192.168.1.11,IT部

    Returns:
        list[dict]: 资产列表
    """
    reader = csv.DictReader(io.StringIO(content), delimiter=delimiter)
    assets = []
    for i, row in enumerate(reader, 2):
        product = (row.get("product") or row.get("产品") or row.get("Product") or "").strip()
        if not product:
            logger.warning(f"CSV 第 {i} 行缺少产品名，跳过")
            continue

        assets.append({
            "product": product,
            "version": (row.get("version") or row.get("版本") or row.get("Version") or "unknown").strip(),
            "host": (row.get("host") or row.get("主机") or row.get("Host") or "").strip(),
            "department": (row.get("department") or row.get("部门") or row.get("Department") or "").strip(),
        })

    logger.info(f"CSV 解析: {len(assets)} 条资产")
    return assets


def parse_excel(file_path: str) -> list[dict]:
    """
    解析 Excel 文件为资产列表

    Excel 格式同 CSV，第一行为表头

    Returns:
        list[dict]: 资产列表
    """
    try:
        import openpyxl
    except ImportError:
        logger.error("openpyxl 未安装，无法解析 Excel。运行: pip install openpyxl")
        return []

    wb = openpyxl.load_workbook(file_path, read_only=True)
    ws = wb.active

    rows = list(ws.iter_rows(values_only=True))
    if not rows:
        return []

    # 解析表头（支持中英文）
    header = [str(c).strip().lower() if c else "" for c in rows[0]]
    col_map = {
        "product": _find_col(header, ["product", "产品", "产品名"]),
        "version": _find_col(header, ["version", "版本"]),
        "host": _find_col(header, ["host", "主机", "ip", "地址"]),
        "department": _find_col(header, ["department", "部门", "业务线"]),
    }

    assets = []
    for i, row in enumerate(rows[1:], 2):
        product = str(row[col_map["product"]] or "").strip() if col_map["product"] is not None else ""
        if not product:
            continue

        version = str(row[col_map["version"]] or "unknown").strip() if col_map["version"] is not None else "unknown"
        host = str(row[col_map["host"]] or "").strip() if col_map["host"] is not None else ""
        department = str(row[col_map["department"]] or "").strip() if col_map["department"] is not None else ""

        assets.append({
            "product": product,
            "version": version,
            "host": host,
            "department": department,
        })

    wb.close()
    logger.info(f"Excel 解析: {len(assets)} 条资产")
    return assets


def _find_col(header: list[str], candidates: list[str]) -> int | None:
    """在表头中查找匹配的列索引"""
    for i, h in enumerate(header):
        if h in candidates:
            return i
    return None


def import_assets(assets: list[dict], source: str = "manual") -> dict:
    """
    批量导入资产到数据库

    Returns:
        dict: 导入统计
    """
    from database.db_manager import add_asset_to_db

    stats = {"total": len(assets), "added": 0, "updated": 0, "errors": 0}

    for asset in assets:
        try:
            result = add_asset_to_db(
                product=asset["product"],
                version=asset.get("version", "unknown"),
                host=asset.get("host", ""),
                department=asset.get("department", ""),
            )
            if result == "added":
                stats["added"] += 1
            else:
                stats["updated"] += 1
        except Exception as e:
            logger.error(f"资产导入失败 {asset['product']}: {e}")
            stats["errors"] += 1

    logger.info(f"资产导入完成: {stats}")
    return stats


def generate_csv_template() -> str:
    """生成 CSV 模板"""
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["product", "version", "host", "department"])
    writer.writerow(["Apache", "2.4", "192.168.1.10", "IT部"])
    writer.writerow(["Nginx", "1.24", "192.168.1.11", "IT部"])
    writer.writerow(["OpenSSL", "3.0", "192.168.1.12", "IT部"])
    return output.getvalue()
