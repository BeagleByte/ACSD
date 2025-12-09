"""
Agno agents for collecting CVE and hacking news data.

This module defines three autonomous agents that collect security intelligence:
1. CVECollectorAgent - Fetches CVE vulnerability data from NVD (National Vulnerability Database)
2. HackingNewsAgent - Collects hacking/security news from public sources (Hacker News, BleepingComputer)
3. DarknetNewsAgent - Monitors darknet forums for threat intelligence (optional, requires Tor)

Each agent runs independently and stores collected data in PostgreSQL database.
Agents are orchestrated by the TaskScheduler which runs them on a schedule.

Installation:  pip install agno
"""

# ==================== IMPORTS ====================
from agno.agent import Agent
# Agent:  Base class from Agno framework that handles tool calling, memory, and LLM interactions
# An Agent is an autonomous entity that can use tools (like WebsiteTools) to accomplish tasks

from agno.models. ollama import Ollama
# OpenAIChat: LLM model wrapper for OpenAI's API (gpt-4-turbo, gpt-4, etc.)
# Other options: anthropic. Claude, replicate models, etc.
# The model is what "thinks" and decides which tools to use and how to respond

from agno.tools.website import WebsiteTools
# WebsiteTools: Agno toolkit for reading/scraping website content
# Methods include: read_url(url), add_website_to_knowledge_base(url)
# Uses BeautifulSoup4 internally to parse HTML

import os
# os:  For reading environment variables (API keys, config)

import feedparser
# feedparser: Library for parsing RSS/Atom feeds
# Used to fetch news from RSS feeds (Hacker News, BleepingComputer)

import httpx
# httpx: Async HTTP client (similar to requests but better for async)
# Used to fetch JSON data from APIs (NVD feeds)

import json
# json:  For parsing/serializing JSON data

from datetime import datetime
# datetime: For timestamp handling, recording when CVEs/news were published

from database import SessionLocal, CVE, HackingNews, AgentRun
# SessionLocal: Factory for creating database sessions
# CVE, HackingNews, AgentRun: SQLAlchemy ORM models (database tables)

from sqlalchemy. orm import Session
# Session: Type hint for database session objects

from typing import Optional
# Optional: Type hint for optional function parameters

import logging
# logging:  For recording agent activity and errors

# Configure logger for this module
# Logs will show which agent is running, what it found, and any errors
logger = logging.getLogger(__name__)


# ==================== CVE COLLECTOR AGENT ====================

class CVECollectorAgent:
    """
    Autonomous agent that collects CVE (Common Vulnerabilities and Exposures) data.

    What it does:
    - Fetches CVE data from NVD (National Vulnerability Database) JSON feed
    - Parses CVE details:  ID, severity, CVSS score, affected products, references
    - Checks if CVE already exists in database (avoid duplicates)
    - Stores new CVEs in PostgreSQL database
    - Records execution metadata (items collected, status, errors)

    The agent uses an LLM (gpt-4-turbo) and WebsiteTools to potentially enhance
    its capabilities, but for NVD we use direct HTTP requests (more reliable).
    """

    def __init__(self):
        """
        Initialize the CVE collector agent with:
        1. Agent name and LLM model (for future enhancements)
        2. Tools available to the agent (WebsiteTools)
        3. Instructions/system prompt guiding agent behavior
        """
        self.agent = Agent(
            # Name identifier for this agent
            name="cve-collector",

            # LLM model to use for decision-making and reasoning
            # gpt-4-turbo:  Latest OpenAI model, good balance of cost/performance
            # Requires OPENAI_API_KEY env var
            #ToDo -> select the right model
            model=Ollama(id="gpt-4-turbo"),

            # Tools this agent can use to accomplish its tasks
            # WebsiteTools allows it to read and parse web content if needed
            tools=[WebsiteTools()],

            # System instructions/prompt that guides agent behavior
            # Tells the agent what its role is, what sources to check, what to extract
            instructions="""
            You are a CVE intelligence agent. Your job is to:
            1. Fetch CVE data from NVD RSS feeds and other sources
            2. Parse and enrich CVE information
            3. Extract severity, affected products, and references
            4. Store normalized data in the database
            
            Sources to check:
            - NVD RSS:  https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json
            - Mitre:  https://www.cvedetails.com/
            
            Ensure all CVE records include:  cve_id, title, description, severity, cvss_score, affected_products, references. 
            """,

            # Enable markdown formatting in responses
            markdown=True
        )

    def run(self, db:  Session) -> dict:
        """
        Main execution method for the CVE collector agent.

        Flow:
        1. Create an AgentRun record to track this execution
        2. Call _fetch_nvd_feed() to collect CVEs
        3. Update the AgentRun record with results (success/failure)
        4. Return summary dict

        Args:
            db (Session): Database session for storing records

        Returns:
            dict: Result status and count of CVEs collected
                  Example: {"status": "success", "cves_collected": 25}
        """

        # Create a record in agent_runs table to track this execution
        # Status starts as "running"
        run_record = AgentRun(agent_name="cve_agent", status="running")
        db.add(run_record)
        db.commit()

        try:
            # Log that execution is starting
            logger.info("Starting CVE collection...")

            # Call the main collection method - this fetches CVEs from NVD
            # Returns a list of CVE objects that were added to database
            cves_collected = self._fetch_nvd_feed(db)

            # Update the execution record with success info
            run_record.status = "success"  # Mark as completed successfully
            run_record.items_collected = len(cves_collected)  # How many CVEs we found
            run_record.items_processed = len(cves_collected)  # How many we processed
            run_record.completed_at = datetime.utcnow()  # When it finished
            db.commit()  # Save to database

            # Log successful completion
            logger.info(f"CVE collection completed: {len(cves_collected)} CVEs")

            # Return result to caller
            return {"status": "success", "cves_collected": len(cves_collected)}

        except Exception as e:
            # If anything goes wrong, catch the exception
            logger.error(f"CVE collection failed: {str(e)}")

            # Mark execution as failed and record the error message
            run_record.status = "failed"
            run_record.error_message = str(e)
            run_record.completed_at = datetime.utcnow()
            db.commit()

            # Return error info
            return {"status": "failed", "error": str(e)}

    def _fetch_nvd_feed(self, db: Session) -> list:
        """
        Fetch CVE data from NVD JSON feed and store in database.

        Process:
        1. Make HTTP GET request to NVD recent CVEs JSON endpoint
        2. Parse the JSON response
        3. For each CVE in the feed:
           - Extract CVE ID, title, description, severity, CVSS score
           - Check if it already exists in database (avoid duplicates)
           - Create CVE object and add to session
        4. Commit all new CVEs to database

        Args:
            db (Session): Database session

        Returns:
            list:  List of CVE objects that were added
        """

        # NVD official JSON feed containing recent CVE data
        # This endpoint returns the latest CVEs with all their metadata
        url = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json"

        # List to collect CVE objects we're adding
        cves = []

        try:
            # Make HTTP request to fetch the NVD feed
            # timeout=30 seconds:  if feed doesn't respond in 30s, fail gracefully
            response = httpx.get(url, timeout=30)

            # Raise exception if HTTP status is not 2xx (200-299)
            # This catches 404, 500, etc.
            response.raise_for_status()

            # Parse JSON response into Python dict
            data = response.json()

            # Iterate through CVE items in the response
            # [: 50] limits to first 50 items to avoid overload (can adjust or remove)
            for item in data. get("CVE_Items", [])[:50]:

                # Extract the "cve" object which contains CVE metadata
                cve_data = item.get("cve", {})

                # Extract the "impact" object which contains severity/CVSS info
                impact = item.get("impact", {})

                # Get the CVE ID (e.g., "CVE-2024-1234")
                # Nested in cve -> CVE_data_meta -> ID
                cve_id = cve_data.get("CVE_data_meta", {}).get("ID")

                # If no CVE ID found, skip this item
                if not cve_id:
                    continue

                # Check if this CVE is already in database
                # Query CVE table for matching cve_id
                existing = db.query(CVE).filter(CVE.cve_id == cve_id).first()

                # If it already exists, skip it (avoid duplicates)
                if existing:
                    continue

                # Create new CVE record with extracted data
                cve = CVE(
                    # Unique identifier for the vulnerability
                    cve_id=cve_id,

                    # Vulnerability title (same as CVE ID in NVD feed)
                    title=cve_data.get("CVE_data_meta", {}).get("ID", ""),

                    # Detailed description from description_data array
                    # Join multiple descriptions with semicolon separator
                    description="; ".join([
                        d.get("value", "")
                        for d in cve_data.get("description", {}).get("description_data", [])
                    ]),

                    # Severity level (CRITICAL, HIGH, MEDIUM, LOW)
                    # Located in impact -> baseMetricV3 -> cvssV3 -> baseSeverity
                    severity=impact.get("baseMetricV3", {}).get("cvssV3", {}).get("baseSeverity", "UNKNOWN"),

                    # CVSS v3 numeric score (0-10)
                    # Example: "9.8" means critical vulnerability
                    cvss_score=str(impact.get("baseMetricV3", {}).get("cvssV3", {}).get("baseScore", "N/A")),

                    # Data source identifier
                    # "nvd" means this came from National Vulnerability Database
                    source="nvd",

                    # When the vulnerability was published
                    # Parse ISO format date (e.g., "2024-01-15T12:30:00Z")
                    published_date=datetime.fromisoformat(
                        item.get("publishedDate", "").replace("Z", "+00:00")
                    ),
                )

                # Add this CVE object to database session
                # It won't be persisted until db.commit() is called
                db.add(cve)

                # Track that we added this CVE
                cves.append(cve)

            # Commit all pending CVE records to database
            # This executes an INSERT statement for all new CVEs
            db.commit()

        except Exception as e:
            # If anything fails (network error, JSON parse error, etc.)
            logger.error(f"Error fetching NVD feed: {e}")
            # Don't crash, just log and return empty list

        # Return list of CVEs we added
        return cves


# ==================== HACKING NEWS AGENT ====================

class HackingNewsAgent:
    """
    Autonomous agent that collects hacking and security news.

    What it does:
    - Scrapes multiple news sources via RSS feeds:
      * Hacker News (popular tech/security news)
      * BleepingComputer (security-focused news)
    - Extracts news metadata:  title, content, source, category, relevance
    - Avoids duplicate articles by checking URLs
    - Stores articles in HackingNews table
    - Assigns relevance scores to help prioritize important news

    The agent can be extended to include:
    - Reddit security subreddits
    - Twitter/X security researchers
    - Custom security blogs/feeds
    """

    def __init__(self):
        """
        Initialize the hacking news agent with LLM and tools.

        The agent uses GPT-4-turbo to potentially analyze news content,
        categorize it, and assign relevance scores.
        """
        self.agent = Agent(
            name="hacking-news-agent",

            # LLM model for reasoning about news relevance and categorization
            #ToDo
            model=Ollama(id="gpt-4-turbo"),

            # Tools available (can use WebsiteTools to scrape news sites if needed)
            tools=[WebsiteTools()],

            # Instructions guiding agent behavior for news collection
            instructions="""
            You are a hacking news aggregator agent.  Collect news from: 
            1. Hacker News (via RSS or API)
            2. Reddit security subreddits (r/hacking, r/netsec, r/cybersecurity)
            3. SecurityFocus
            4. BleepingComputer
            5. Twitter/X (security researchers, accounts)
            
            For each news item, extract:
            - Title
            - Content/description
            - Source
            - Category (exploit, breach, threat, tool, advisory, etc.)
            - Relevance score (0-100) based on severity and impact
            
            Avoid duplicates by checking source URLs. 
            """,
            markdown=True
        )

    def run(self, db: Session) -> dict:
        """
        Main execution method for the hacking news agent.

        Flow:
        1. Create AgentRun record to track execution
        2. Fetch news from multiple sources (Hacker News + BleepingComputer)
        3. Combine results and update execution record
        4. Return summary

        Args:
            db (Session): Database session

        Returns:
            dict:  Result status and count of news items collected
                  Example: {"status":  "success", "news_collected": 15}
        """

        # Create execution tracking record
        run_record = AgentRun(agent_name="news_agent", status="running")
        db.add(run_record)
        db.commit()

        try:
            logger.info("Starting hacking news collection...")

            # Fetch news from multiple sources
            # _fetch_hacker_news() returns list of HackingNews objects
            # _fetch_bleepingcomputer() returns list of HackingNews objects
            # Combine both lists into one
            news_items = self._fetch_hacker_news(db) + self._fetch_bleepingcomputer(db)

            # Update execution record with success status
            run_record.status = "success"
            run_record.items_collected = len(news_items)
            run_record.items_processed = len(news_items)
            run_record.completed_at = datetime.utcnow()
            db.commit()

            logger.info(f"News collection completed: {len(news_items)} items")
            return {"status": "success", "news_collected": len(news_items)}

        except Exception as e:
            # Handle any errors that occur during collection
            logger.error(f"News collection failed: {str(e)}")

            # Record failure in execution tracking
            run_record.status = "failed"
            run_record.error_message = str(e)
            run_record.completed_at = datetime.utcnow()
            db.commit()

            return {"status":  "failed", "error": str(e)}

    def _fetch_hacker_news(self, db: Session) -> list:
        """
        Fetch news from Hacker News via RSS feed.

        Hacker News (news.ycombinator.com):
        - Popular tech news aggregator
        - Has security-related discussions
        - RSS feed contains recent top stories

        Process:
        1. Fetch RSS feed from Hacker News
        2. Parse each entry (news item)
        3. Check if already in database (by URL)
        4. Extract and store news metadata
        5. Assign default relevance score

        Args:
            db (Session): Database session

        Returns:
            list:  List of HackingNews objects added
        """

        # Official Hacker News RSS feed URL
        url = "https://news.ycombinator.com/rss"

        # List to collect news items
        items = []

        try:
            # Parse RSS feed using feedparser library
            # Returns a FeedParserDict with entries list
            feed = feedparser.parse(url)

            # Iterate through entries in the feed
            # [: 20] limits to first 20 items to avoid overload
            for entry in feed.entries[: 20]:

                # Get the URL of the news article
                # This will be our unique identifier (no duplicates)
                source_url = entry.get("link", "")

                # Check if this URL already exists in database
                existing = db.query(HackingNews).filter(
                    HackingNews.source_url == source_url
                ).first()

                # Skip if already in database (avoid duplicates)
                if existing:
                    continue

                # Create new HackingNews record
                news = HackingNews(
                    # Article headline/title
                    title=entry. get("title", ""),

                    # Article summary/content (limit to 1000 chars to avoid huge entries)
                    content=entry.get("summary", "")[:1000],

                    # Which source this came from
                    source="hacker_news",

                    # Unique URL identifier for this article
                    source_url=source_url,

                    # When the article was published
                    # Convert RSS parsed_time to Python datetime
                    # If no date found, use current time
                    published_date=(
                        datetime(*entry.published_parsed[: 6])
                        if hasattr(entry, 'published_parsed')
                        else datetime.utcnow()
                    ),

                    # Category/type of news
                    category="news",  # General news (not specialized)

                    # Relevance score 0-100
                    # 50 = moderate relevance (default)
                    # Can be refined later by LLM if needed
                    relevance_score=50
                )

                # Add to database session
                db.add(news)

                # Track that we added this item
                items.append(news)

            # Commit all new news items to database
            db.commit()

        except Exception as e:
            # Log error but don't crash
            logger.error(f"Error fetching Hacker News: {e}")

        return items

    def _fetch_bleepingcomputer(self, db: Session) -> list:
        """
        Fetch news from BleepingComputer via RSS feed.

        BleepingComputer (bleepingcomputer.com):
        - Dedicated security/tech news site
        - Focus on:  vulnerabilities, breaches, malware, exploits
        - More relevant to security operations than general tech news

        Process:
        1. Fetch RSS feed from BleepingComputer
        2. Parse entries
        3. Check for duplicates by URL
        4. Extract and store with higher default relevance score
        5. Mark category as "breach" since BC focuses on security

        Args:
            db (Session): Database session

        Returns:
            list: List of HackingNews objects added
        """

        # BleepingComputer RSS feed
        url = "https://www.bleepingcomputer.com/feed/"

        # List to collect news items
        items = []

        try:
            # Parse the RSS feed
            feed = feedparser.parse(url)

            # Iterate through feed entries
            # [:20] limits to 20 items
            for entry in feed.entries[: 20]:

                # Get article URL (unique identifier)
                source_url = entry.get("link", "")

                # Check if already in database
                existing = db.query(HackingNews).filter(
                    HackingNews.source_url == source_url
                ).first()

                # Skip duplicates
                if existing:
                    continue

                # Create new news record
                news = HackingNews(
                    title=entry.get("title", ""),
                    content=entry. get("summary", "")[:1000],
                    source="bleepingcomputer",  # Source identifier
                    source_url=source_url,

                    # Parse published date from RSS entry
                    published_date=(
                        datetime(*entry.published_parsed[:6])
                        if hasattr(entry, 'published_parsed')
                        else datetime.utcnow()
                    ),

                    # BleepingComputer focuses on breaches/vulnerabilities
                    # Mark category as "breach" for prioritization
                    category="breach",

                    # Higher relevance score (70 vs 50) because BC is security-focused
                    # More likely to contain important security intelligence
                    relevance_score=70
                )

                # Add to database session
                db.add(news)
                items.append(news)

            # Commit all new items
            db.commit()

        except Exception as e:
            # Log error but don't crash
            logger.error(f"Error fetching BleepingComputer: {e}")

        return items


# ==================== DARKNET NEWS AGENT ====================

class DarknetNewsAgent:
    """
    Autonomous agent for monitoring darknet forums and threat actor activity.

    What it does:
    - Monitors darknet markets and forums for:
      * Exploit kits and 0-day vulnerabilities being sold/discussed
      * Threat actor announcements and activity
      * Leaked data and breach notifications
      * New malware and tools
    - Requires Tor network access and SOCKS5 proxy setup
    - Extracts and categorizes intelligence
    - Stores findings in database for analysis

    IMPORTANT NOTES:
    - This is OPTIONAL and disabled by default
    - Requires legal authorization and careful operation
    - Set DARKNET_ENABLED=true in . env to enable
    - Requires Tor Browser/Tor daemon running
    - Use for authorized security research and threat intelligence only

    Currently a placeholder - real implementation would need:
    - Stem library (Tor control)
    - BeautifulSoup (HTML parsing)
    - SOCKS5 proxy configuration
    - Careful source selection
    """

    def __init__(self, use_tor:  bool = False):
        """
        Initialize darknet agent.

        Args:
            use_tor (bool): Whether Tor is available and configured.
                          Set to False to disable darknet collection.
        """

        # Store whether Tor is available
        self. use_tor = use_tor

        # Initialize the agent (similar to others)
        #ToDo
        self.agent = Agent(
            name="darknet-agent",
            model=Ollama(id="gpt-4-turbo"),
            tools=[WebsiteTools()],
            instructions="""
            You are a darknet intelligence agent. Your role is to: 
            1. Monitor darknet forums (via Tor, if enabled)
            2. Track threat actor activity on known forums (Dream Market, Breach forums, etc.)
            3. Aggregate exploit kits, 0-days, and vulnerability discussions
            4. Flag emerging threats
            
            Note: This requires Tor browser/socks5 proxy configured. 
            Focus on high-signal sources only.
            """,
            markdown=True
        )

    def run(self, db: Session) -> dict:
        """
        Main execution method for darknet agent.

        Early exit if Tor is not configured:
        - Darknet collection requires Tor SOCKS5 proxy
        - If use_tor=False, returns "skipped" status
        - Prevents errors from attempting to access . onion sites without Tor

        Args:
            db (Session): Database session

        Returns:
            dict:  Execution status
                  If Tor disabled: {"status": "skipped", "reason": "Tor not configured"}
                  If successful: {"status": "success", "darknet_news_collected": N}
                  If failed: {"status": "failed", "error": error_message}
        """

        # Check if Tor is available
        # If not, skip execution (darknet requires Tor)
        if not self.use_tor:
            logger.warning("Darknet agent disabled (Tor not configured)")
            # Return early without doing anything
            return {"status": "skipped", "reason": "Tor not configured"}

        # Create execution tracking record
        run_record = AgentRun(agent_name="darknet_agent", status="running")
        db.add(run_record)
        db.commit()

        try:
            logger. info("Starting darknet news collection...")

            # Call the collection method
            # Currently returns empty list (placeholder)
            news_items = self._fetch_darknet_forums(db)

            # Update execution record with success
            run_record.status = "success"
            run_record. items_collected = len(news_items)
            run_record. items_processed = len(news_items)
            run_record.completed_at = datetime.utcnow()
            db.commit()

            logger.info(f"Darknet collection completed: {len(news_items)} items")
            return {"status": "success", "darknet_news_collected": len(news_items)}

        except Exception as e:
            # Handle errors during collection
            logger.error(f"Darknet collection failed: {str(e)}")

            # Record failure
            run_record.status = "failed"
            run_record.error_message = str(e)
            run_record. completed_at = datetime.utcnow()
            db.commit()

            return {"status": "failed", "error": str(e)}

    def _fetch_darknet_forums(self, db: Session) -> list:
        """
        Placeholder method for fetching darknet forum data.

        CURRENT STATUS:  Placeholder implementation (returns empty list)

        FULL IMPLEMENTATION WOULD REQUIRE:
        ===================================

        1. Tor Connection Setup:
           - Install:  pip install stem pysocks
           - Start Tor daemon:  tor --socks-port 9050
           - Use stem library to control Tor:
             from stem import Signal
             from stem.control import Controller

        2. HTTP Requests via Tor:
           - Configure httpx with SOCKS5 proxy
           - proxy="socks5://localhost:9050"

        3. Darknet Forum Scraping:
           - Known forums: Dream Market, Breach forums, Russian Market
           - Use BeautifulSoup to parse HTML
           - Extract:  threats, exploits, announcements
           - Parse timestamps and extract key intelligence

        4. Intelligence Extraction:
           - Use NLP/regex to identify:
             * Exploit mentions and descriptions
             * 0-day vulnerability discussions
             * Malware samples available
             * Breach announcements
           - Assign severity scores
           - Link to affected companies/products

        5. Data Storage:
           - Create HackingNews records with:
             * is_darknet=True flag
             * High relevance scores (80-100)
             * category="exploit", "threat", "malware"
             * Metadata with forum source, actor names

        6. Security Considerations:
           - Use VPN + Tor for extra anonymity
           - Don't interact with sellers/actors
           - Monitor for law enforcement presence
           - Keep logs encrypted
           - Comply with all applicable laws

        Example structure:
        ```
        try:
            # Create SOCKS5 session
            proxies = {"https://":  "socks5://localhost:9050"}

            # List of known darknet forum URLs (. onion)
            forums = [
                "http://example-market.onion",
                "http://breach-forum.onion"
            ]

            for forum_url in forums:
                response = httpx.get(forum_url, proxies=proxies, timeout=30)
                soup = BeautifulSoup(response.text, 'html.parser')

                # Extract posts, parse threat intelligence
                # Store in HackingNews with is_darknet=True
        ```

        Args:
            db (Session): Database session

        Returns:
            list: List of darknet intelligence items collected
                  Currently:  empty list (placeholder)
        """

        # Log that this is not implemented yet
        logger.info("Darknet agent:  placeholder (requires Tor setup)")

        # Return empty list
        # Real implementation would parse . onion forums and return HackingNews objects
        return []