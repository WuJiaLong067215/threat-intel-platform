"""
测试 MongoDB 连接
运行: python test_db.py
"""
from database.db_manager import test_connection, get_stats

if __name__ == "__main__":
    print("🔍 测试 MongoDB 连接...")
    ok = test_connection()
    if ok:
        stats = get_stats()
        print(f"📊 数据库统计: {stats}")
