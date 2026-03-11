"""
调度器 - 定时任务管理
"""
import schedule
import time
from datetime import datetime
from core.intel_engine import run_full_pipeline


class Scheduler:
    def __init__(self):
        self._jobs = []
        self._running = False

    def add_crawl_job(self, interval_minutes=120, days_back=7, check_exploit=True):
        """添加定时采集任务"""
        def job():
            run_full_pipeline(days_back=days_back, check_exploit_flag=check_exploit)

        schedule.every(interval_minutes).minutes.do(job)
        self._jobs.append({
            "name": f"NVD 采集 (每 {interval_minutes} 分钟)",
            "func": job,
            "next_run": "按计划执行",
        })
        print(f"⏰ 已注册: NVD 采集任务，间隔 {interval_minutes} 分钟")

    def add_daily_report(self, hour=8, minute=0):
        """添加每日报告任务"""
        schedule.every().day.at(f"{hour:02d}:{minute:02d}").do(
            run_full_pipeline, days_back=1, check_exploit_flag=True
        )
        self._jobs.append({
            "name": f"每日安全简报 ({hour:02d}:{minute:02d})",
            "func": None,
            "next_run": f"每天 {hour:02d}:{minute:02d}",
        })
        print(f"⏰ 已注册: 每日简报任务，{hour:02d}:{minute:02d}")

    def list_jobs(self):
        """列出所有任务"""
        return self._jobs

    def run(self):
        """启动调度循环"""
        self._running = True
        print(f"\n🚀 调度器启动 | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        for job in self._jobs:
            print(f"   - {job['name']}")

        while self._running:
            schedule.run_pending()
            time.sleep(10)

    def stop(self):
        """停止调度"""
        self._running = False
        print("🛑 调度器已停止")


# 全局调度器实例
scheduler = Scheduler()
