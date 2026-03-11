"""
威胁情报平台 - 主入口
"""
from datetime import datetime
from database.db_manager import test_connection, init_collections
from core.intel_engine import run_full_pipeline
from scheduler.job import scheduler


def main():
    print("🛡️ 威胁情报平台启动中...")
    print(f"   时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()

    # 1. 数据库连接 + 初始化
    if not test_connection():
        print("❌ 数据库未就绪，请先启动 MongoDB")
        return

    init_collections()

    # 2. 首次执行完整流水线
    run_full_pipeline(days_back=7, check_exploit_flag=True)

    # 3. 注册定时任务
    scheduler.add_crawl_job(interval_minutes=120, days_back=7)
    scheduler.add_daily_report(hour=8, minute=0)

    # 4. 启动调度器
    scheduler.run()


if __name__ == "__main__":
    main()
