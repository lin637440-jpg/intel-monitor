from apscheduler.schedulers.blocking import BlockingScheduler
from apscheduler.triggers.interval import IntervalTrigger

from app.monitor.collectors_registry import collect_source
from metrics import compute_metrics

OTHER_SOURCES = ["GitHub Advisories", "Hugging Face Blog", "安全客", "ArXiv", "OSV.dev"]


def job_nvd():
    print("\n=== [定时] NVD ===")
    collect_source("NVD")
    compute_metrics()


def job_others():
    print("\n=== [定时] 其他源 ===")
    for src in OTHER_SOURCES:
        collect_source(src)
    compute_metrics()


def main():
    scheduler = BlockingScheduler(timezone="Asia/Shanghai")

    scheduler.add_job(job_nvd, IntervalTrigger(hours=1), id="nvd")
    scheduler.add_job(job_others, IntervalTrigger(hours=4), id="others")

    print("调度器已启动：NVD 每小时，其他源每 4 小时")
    print("Ctrl+C 退出")
    try:
        scheduler.start()
    except (KeyboardInterrupt, SystemExit):
        print("调度器停止")


if __name__ == "__main__":
    main()