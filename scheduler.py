"""
Background task scheduler using APScheduler.
Runs agents on a schedule to keep data fresh.
"""
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger
import logging
import os
from datetime import datetime
from database import SessionLocal, get_db
from agents import CVECollectorAgent, HackingNewsAgent, DarknetNewsAgent

logger = logging.getLogger(__name__)


class TaskScheduler:
    def __init__(self):
        self.scheduler = BackgroundScheduler()
        self.cve_agent = CVECollectorAgent()
        self.news_agent = HackingNewsAgent()
        self.darknet_agent = DarknetNewsAgent(use_tor=os.getenv("DARKNET_ENABLED", "false").lower() == "true")

    def start(self):
        """Start the scheduler"""
        # CVE collection every hour
        self.scheduler.add_job(
            self._run_cve_agent,
            trigger=IntervalTrigger(hours=1),
            id="cve_job",
            name="CVE Collection",
            replace_existing=True
        )

        # Hacking news every 30 minutes
        self.scheduler.add_job(
            self._run_news_agent,
            trigger=IntervalTrigger(minutes=30),
            id="news_job",
            name="Hacking News Collection",
            replace_existing=True
        )

        # Darknet news every 6 hours (if enabled)
        if os.getenv("DARKNET_ENABLED", "false").lower() == "true":
            self.scheduler.add_job(
                self._run_darknet_agent,
                trigger=IntervalTrigger(hours=6),
                id="darknet_job",
                name="Darknet News Collection",
                replace_existing=True
            )

        self.scheduler.start()
        logger.info("Task scheduler started")

    def stop(self):
        """Stop the scheduler"""
        self.scheduler.shutdown()
        logger.info("Task scheduler stopped")

    def _run_cve_agent(self):
        """Run CVE agent in background"""
        db = SessionLocal()
        try:
            logger.info("[Scheduled] Running CVE agent...")
            result = self.cve_agent.run(db)
            logger.info(f"[Scheduled] CVE agent result: {result}")
        except Exception as e:
            logger.error(f"[Scheduled] CVE agent failed: {e}")
        finally:
            db.close()

    def _run_news_agent(self):
        """Run news agent in background"""
        db = SessionLocal()
        try:
            logger.info("[Scheduled] Running hacking news agent...")
            result = self.news_agent.run(db)
            logger.info(f"[Scheduled] News agent result: {result}")
        except Exception as e:
            logger.error(f"[Scheduled] News agent failed: {e}")
        finally:
            db.close()

    def _run_darknet_agent(self):
        """Run darknet agent in background"""
        db = SessionLocal()
        try:
            logger.info("[Scheduled] Running darknet agent...")
            result = self.darknet_agent.run(db)
            logger.info(f"[Scheduled] Darknet agent result: {result}")
        except Exception as e:
            logger.error(f"[Scheduled] Darknet agent failed: {e}")
        finally:
            db.close()