"""
数据库模块 - 标准化数据存储层

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

load_dotenv()

# 集合名称
COL_CVES = "cves"
COL_ASSETS = "assets"
COL_RISKS = "risks"
COL_REPORTS = "reports"


def get_client() -> MongoClient:
    uri = os.getenv("MONGO_URI", "mongodb://localhost:27017/")
    return MongoClient(uri)


def get_db():
    client = get_client()
    return client[os.getenv("MONGO_DB", "threat_intel")]


def init_collections():
    """初始化集合和索引"""
    db = get_db()

    # CVEs 索引
    try:
        db[COL_CVES].create_index([("cve_id", ASCENDING)], unique=True)
    except Exception:
        # 已有重复数据，先去重再建索引
        print("⚠️ CVE 存在重复数据，正在去重...")
        pipeline = [
            {"$group": {"_id": "$cve_id", "count": {"$sum": 1}, "ids": {"$push": "$_id"}}},
            {"$match": {"count": {"$gt": 1}}},
        ]
        for doc in db[COL_CVES].aggregate(pipeline):
            # 保留第一个，删除其余
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
    """批量插入/更新 CVE（去重）"""
    if not data_list:
        return 0
    db = get_db()
    count = 0
    for cve in data_list:
        result = db[COL_CVES].update_one(
            {"cve_id": cve["cve_id"]},
            {"$set": {**cve, "updated_at": datetime.now().isoformat()}},
            upsert=True,
        )
        if result.upserted_id or result.modified_count:
            count += 1
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
# 资产操作
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


def remove_asset_from_db(product, version="unknown"):
    """从数据库删除资产"""
    db = get_db()
    result = db[COL_ASSETS].delete_one({"product": product, "version": version})
    return result.deleted_count > 0


def get_all_assets():
    """获取所有资产"""
    db = get_db()
    return list(db[COL_ASSETS].find({}, {"_id": 0}))


# ═══════════════════════════════════
# 风险操作
# ═══════════════════════════════════

def upsert_risks(risk_list):
    """批量写入风险关联"""
    if not risk_list:
        return 0
    db = get_db()
    count = 0
    for risk in risk_list:
        result = db[COL_RISKS].update_one(
            {"cve_id": risk["cve_id"], "product": risk["product"]},
            {"$set": {**risk, "updated_at": datetime.now().isoformat()}},
            upsert=True,
        )
        if result.upserted_id or result.modified_count:
            count += 1
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
