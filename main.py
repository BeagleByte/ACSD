"""
Main entry point:  start API server and scheduler, then dashboard.
"""
import logging
import os
import sys
from dotenv import load_dotenv
import threading
import time
from fastapi import FastAPI
from uvicorn import Config, Server
from scheduler import TaskScheduler
from api import app as api_app

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def run_api_server():
    """Run FastAPI server in a thread"""
    config = Config(
        app=api_app,
        host=os.getenv("API_HOST", "0.0.0.0"),
        port=int(os.getenv("API_PORT", 8000)),
        log_level="info"
    )
    server = Server(config)
    asyncio.run(server.serve())


async def run_dashboard():
    """Run Dash dashboard in a thread (optional, or serve separately)"""
    from dashboard import app as dash_app
    dash_app.run_server(
        host=os.getenv("DASH_HOST", "0.0.0.0"),
        port=int(os.getenv("DASH_PORT", 8050)),
        debug=False
    )


if __name__ == "__main__":
    logger.info("Starting CVE Intelligence System...")

    # Initialize database
    from database import init_db

    init_db()
    logger.info("✓ Database initialized")

    # Start task scheduler
    scheduler = TaskScheduler()
    scheduler.start()
    logger.info("✓ Task scheduler started")

    # Start FastAPI server
    api_thread = threading.Thread(target=run_api_server, daemon=False)
    api_thread.start()
    logger.info("✓ API server started (http://0.0.0.0:8000)")

    # Start Dash dashboard (in separate process for production, or same process for dev)
    logger.info("✓ Dashboard available at http://0.0.0.0:8050")
    logger.info("\n" + "=" * 60)
    logger.info("CVE Intelligence System is running!")
    logger.info("=" * 60)

    try:
        # Keep main thread alive
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Shutting down...")
        scheduler.stop()
        sys.exit(0)