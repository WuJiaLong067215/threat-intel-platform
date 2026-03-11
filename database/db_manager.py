"""
数据库模块 - 标准化数据存储层（连接池单例版）

4 个核心集合：
- cves: CVE 漏洞情报
- assets: 企业资产
- risks: 资产风险关联
- reports: 情报报告
"""
from pymongo import MongoClient, ASCENDING, DESCENDING
from datetime import datetime
from dotenv import load_dotenv
import os
import threading

load_dotenv()

# 集合名称
COL_CVES = "cves"
COL_ASSETS = "assets"
COL_RISKS = "risks"
COL_REPORTS = "reports"

# ── 单例连接池 ──
_client = None
_db = None
_lock = threading.Lock()


def get_client() -> MongoClient:
    """获取全局 MongoClient 单例"""
    global _client
    if _client is None:
        with _lock:
            if _client is None:
                uri = os.getenv("MONGO_URI", "mongodb://localhost:27017/")
                _client = MongoClient(uri, maxPoolSize=20, minPoolSize=5, connectTimeoutMS=5000)
    return _client


def get_db():
    """获取数据库实例"""
    global _db
    if _db is None:
        with _lock:
            if _db is None:
                _db = get_client()[os.getenv("MONGO_DB", "threat_intel")]
    return _db


def init_collections():
    """初始化集合和索引"""
    db = get_db()

    # CVEs 索引
    try:
        db[COL_CVES].create_index([("cve_id", ASCENDING)], unique=True)
    except Exception:
        print("⚠️ CVE 存在重复数据，正在去重...")
        pipeline = [
            {"$group": {"_id": "$cve_id", "count": {"$sum": 1}, "ids": {"$push": "$_id"}}},
            {"$match": {"count": {"$gt": 1}}},
        ]
        for doc in db[COL_CVES].aggregate(pipeline):
            for oid in doc["ids"][1:]:
                db[COL_CVES].delete_one({"_id": oid})
        db[COL_CVES].create_index([("cve_id", ASCENDING)], unique=True)
        print("   去重完成")
    db[COL_CVES].create_index([("published", DESCENDING)])
    db[COL_CVES].create_index([("severity", ASCENDING)])
    db[COL_CVES].create_index([("score", DESCENDING)])

    # Assets 索引
    db[COL_ASSETS].create_index([("product", ASCENDING), ("version", ASCENDING)], unique=True)

    # Risks 索引
    db[COL_RISKS].create_index([("cve_id", ASCENDING)])
    db[COL_RISKS].create_index([("product", ASCENDING)])
    db[COL_RISKS].create_index([("risk_score", DESCENDING)])

    # Reports 索引
    db[COL_REPORTS].create_index([("date", DESCENDING)], unique=True)

    print("✅ 数据库索引初始化完成")


def test_connection():
    try:
        client = get_client()
        # 触发实际连接
        client.admin.command("ping")
        db = get_db()
        collections = db.list_collection_names()
        print(f"✅ MongoDB 连接成功！数据库: {db.name}, 集合: {collections}")
        return True
    except Exception as e:
        print(f"❌ MongoDB 连接失败: {e}")
        return False


# ═══════════════════════════════════
# CVE 操作
# ═══════════════════════════════════

def upsert_cves(data_list):
    """批量插入/更新 CVE（bulk_write 提升性能）"""
    if not data_list:
        return 0
    db = get_db()
    from pymongo import UpdateOne
    ops = []
    now = datetime.now().isoformat()
    for cve in data_list:
        ops.append(
            UpdateOne(
                {"cve_id": cve["cve_id"]},
                {"$set": {**cve, "updated_at": now}},
                upsert=True,
            )
        )
    result = db[COL_CVES].bulk_write(ops)
    count = result.upserted_count + result.modified_count
    print(f"💾 CVE 入库: 新增/更新 {count} 条")
    return count


def find_cves(query=None, limit=100, skip=0, sort_by="published", sort_order=-1):
    """查询 CVE"""
    db = get_db()
    cursor = db[COL_CVES].find(
        query or {}, {"_id": 0},
    ).sort(sort_by, sort_order).skip(skip).limit(limit)
    return list(cursor)


def find_cve_by_id(cve_id):
    """查单个 CVE"""
    db = get_db()
    return db[COL_CVES].find_one({"cve_id": cve_id}, {"_id": 0})


def get_cve_stats():
    """CVE 统计"""
    db = get_db()
    pipeline = [
        {"$group": {"_id": "$severity", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
    ]
    by_severity = {doc["_id"]: doc["count"] for doc in db[COL_CVES].aggregate(pipeline)}

    exploited = db[COL_CVES].count_documents({"exploit.has_exploit": True})
    total = db[COL_CVES].count_documents({})

    return {
        "total": total,
        "by_severity": by_severity,
        "exploited": exploited,
    }


# ═══════════════════════════════════
# 资产操作（统一使用数据库，不再依赖 JSON 文件）
# ═══════════════════════════════════

def add_asset_to_db(product, version="unknown", host="", department=""):
    """添加资产到数据库"""
    db = get_db()
    result = db[COL_ASSETS].update_one(
        {"product": product, "version": version},
        {"$set": {"host": host, "department": department, "updated_at": datetime.now().isoformat()}},
        upsert=True,
    )
    return "added" if result.upserted_id else "updated"


def remove_asset_from_db(product, version=None):
    """从数据库删除资产"""
    db = get_db()
    query = {"product": product}
    if version:
        query["version"] = version
    result = db[COL_ASSETS].delete_one(query)
    return result.deleted_count > 0


def get_all_assets():
    """获取所有资产（从数据库）"""
    db = get_db()
    return list(db[COL_ASSETS].find({}, {"_id": 0}))


def load_assets():
    """兼容接口：从数据库加载资产列表（替换原 JSON 文件读取）"""
    assets = get_all_assets()
    if assets:
        print(f"📦 已加载 {len(assets)} 个资产（数据库）")
    return assets


# ═══════════════════════════════════
# 风险操作
# ═══════════════════════════════════

def upsert_risks(risk_list):
    """批量写入风险关联"""
    if not risk_list:
        return 0
    db = get_db()
    from pymongo import UpdateOne
    ops = []
    now = datetime.now().isoformat()
    for risk in risk_list:
        ops.append(
            UpdateOne(
                {"cve_id": risk["cve_id"], "product": risk["product"]},
                {"$set": {**risk, "updated_at": now}},
                upsert=True,
            )
        )
    result = db[COL_RISKS].bulk_write(ops)
    count = result.upserted_count + result.modified_count
    return count


def find_risks(query=None, limit=50):
    """查询风险"""
    db = get_db()
    cursor = db[COL_RISKS].find(query or {}, {"_id": 0}).sort("risk_score", -1).limit(limit)
    return list(cursor)


def get_risk_stats():
    """风险统计"""
    db = get_db()
    return {
        "total_risks": db[COL_RISKS].count_documents({}),
        "high_risk": db[COL_RISKS].count_documents({"risk_level": {"$in": ["CRITICAL", "HIGH"]}}),
        "exploited_risks": db[COL_RISKS].count_documents({"exploit.has_exploit": True}),
    }


# ═══════════════════════════════════
# 报告操作
# ═══════════════════════════════════

def save_report_to_db(report_data):
    """保存报告"""
    db = get_db()
    date_str = datetime.now().strftime("%Y-%m-%d")
    db[COL_REPORTS].update_one(
        {"date": date_str},
        {"$set": {**report_data, "updated_at": datetime.now().isoformat()}},
        upsert=True,
    )


def get_latest_reports(limit=10):
    """获取历史报告"""
    db = get_db()
    return list(db[COL_REPORTS].find({}, {"_id": 0}).sort("date", -1).limit(limit))


# ═══════════════════════════════════
# 通用
# ═══════════════════════════════════

def get_dashboard_stats():
    """Dashboard 聚合统计"""
    cve_stats = get_cve_stats()
    risk_stats = get_risk_stats()
    asset_count = len(get_all_assets())

    return {
        "total_cves": cve_stats["total"],
        "severity_distribution": cve_stats["by_severity"],
        "exploited": cve_stats["exploited"],
        "total_risks": risk_stats["total_risks"],
        "high_risk": risk_stats["high_risk"],
        "exploited_risks": risk_stats["exploited_risks"],
        "total_assets": asset_count,
    }
