"""
调度器 - 基于 APScheduler 的定时任务管理（后台运行，不阻塞 API）

特点：
- 后台线程运行，不阻塞 FastAPI
- 支持 interval / cron 两种触发方式
- 可动态增删任务
"""
import logging
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
from apscheduler.triggers.cron import CronTrigger
from datetime import datetime

logger = logging.getLogger(__name__)

scheduler = BackgroundScheduler(
    timezone="Asia/Shanghai",
    job_defaults={
        "coalesce": True,       # 错过的任务合并为一次
        "max_instances": 1,     # 同一任务不并发
        "misfire_grace_time": 3600,  # 错过1小时内的任务仍执行
    }
)


def add_crawl_job(interval_minutes=120, days_back=7, check_exploit=True):
    """添加定时采集任务"""
    from core.intel_engine import run_full_pipeline

    scheduler.add_job(
        run_full_pipeline,
        trigger=IntervalTrigger(minutes=interval_minutes),
        id="nvd_crawl",
        name=f"NVD 采集 (每 {interval_minutes} 分钟)",
        kwargs={"days_back": days_back, "check_exploit_flag": check_exploit},
        replace_existing=True,
    )
    logger.info(f"⏰ 已注册: NVD 采集任务，间隔 {interval_minutes} 分钟")


def add_daily_report(hour=8, minute=0):
    """添加每日报告任务"""
    from core.intel_engine import run_full_pipeline

    scheduler.add_job(
        run_full_pipeline,
        trigger=CronTrigger(hour=hour, minute=minute),
        id="daily_report",
        name=f"每日安全简报 ({hour:02d}:{minute:02d})",
        kwargs={"days_back": 1, "check_exploit_flag": True},
        replace_existing=True,
    )
    logger.info(f"⏰ 已注册: 每日简报任务，{hour:02d}:{minute:02d}")


def start():
    """启动调度器（非阻塞）"""
    if not scheduler.running:
        scheduler.start()
        logger.info(f"🚀 调度器启动 | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        for job in scheduler.get_jobs():
            logger.info(f"   - {job.name} | 下次执行: {job.next_run_time}")


def stop():
    """停止调度器"""
    if scheduler.running:
        scheduler.shutdown(wait=False)
        logger.info("🛑 调度器已停止")


def list_jobs():
    """列出所有任务"""
    return [
        {
            "id": job.id,
            "name": job.name,
            "next_run": str(job.next_run_time) if job.next_run_time else None,
            "trigger": str(job.trigger),
        }
        for job in scheduler.get_jobs()
    ]


def get_status():
    """调度器状态"""
    return {
        "running": scheduler.running,
        "jobs_count": len(scheduler.get_jobs()),
        "jobs": list_jobs(),
    }
