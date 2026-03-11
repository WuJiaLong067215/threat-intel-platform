"""
威胁情报平台 - 主入口（v4.0）

启动方式：
  python main.py              # 生产模式（API + 调度器）
  python main.py --pipeline   # 执行一次完整流水线后退出
"""
import logging
import sys
import uvicorn
from datetime import datetime


def main():
    # 配置日志
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler("memory/app.log", encoding="utf-8"),
        ],
    )
    logger = logging.getLogger("main")

    args = sys.argv[1:]

    if "--pipeline" in args:
        # 单次流水线模式
        from database.db_manager import test_connection, init_collections
        from core.intel_engine import run_full_pipeline

        print("🛡️ 威胁情报平台 — 单次流水线模式")
        print(f"   时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

        if not test_connection():
            print("❌ 数据库未就绪，请先启动 MongoDB")
            sys.exit(1)

        init_collections()
        result = run_full_pipeline(days_back=7, check_exploit_flag=True)
        print(f"\n✅ 结果: {result['status']} | 耗时: {result.get('elapsed_seconds', 0)}s")
    else:
        # API 服务模式
        print("🛡️ 威胁情报平台启动中...")
        print(f"   时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"   地址: http://0.0.0.0:8000")
        print(f"   文档: http://0.0.0.0:8000/docs\n")

        uvicorn.run(
            "app.api:app",
            host="0.0.0.0",
            port=8000,
            reload=False,
            log_level="info",
        )


if __name__ == "__main__":
    main()
