# ==============================
# DNS / DDNS BOT – Version 3.1
# Author: Jawollo07
# Improved & hardened
# ==============================

import discord
from discord.ext import commands, tasks
from discord import app_commands

import os
import requests
import subprocess
import threading
import asyncio
import logging
import json
import uuid

from datetime import datetime
from typing import List, Dict, Any, Optional

from dotenv import load_dotenv
from flask import Flask, render_template, request, jsonify, session
import mysql.connector
from mysql.connector import Error
import miniupnpc

# ------------------------------
# ENV
# ------------------------------
load_dotenv()

CLOUDFLARE_API_TOKEN = os.getenv("CF_API_TOKEN")
ZONE_ID = os.getenv("CF_ZONE_ID")
DISCORD_BOT_TOKEN = os.getenv("DISCORD_BOT_TOKEN")

AUTO_UPDATE_INTERVAL_MIN = int(os.getenv("AUTO_UPDATE_INTERVAL", "10"))
ALLOWED_USER_IDS = [int(x) for x in os.getenv("ALLOWED_USER_IDS", "").split(",") if x]

WEB_USERNAME = os.getenv("WEB_USERNAME", "admin")
WEB_PASSWORD = os.getenv("WEB_PASSWORD", "password")
WEB_PORT = int(os.getenv("WEB_PORT", "5000"))
WEB_HOST = os.getenv("WEB_HOST", "0.0.0.0")

MYSQL_HOST = os.getenv("MYSQL_HOST", "localhost")
MYSQL_PORT = int(os.getenv("MYSQL_PORT", "3306"))
MYSQL_USER = os.getenv("MYSQL_USER", "ddns_user")
MYSQL_PASSWORD = os.getenv("MYSQL_PASSWORD", "ddns_password")
MYSQL_DATABASE = os.getenv("MYSQL_DATABASE", "ddns_bot")

CERTBOT_DOMAINS = [d.strip() for d in os.getenv("CERTBOT_DOMAINS", "").split(",") if d]
CERTBOT_EMAIL = os.getenv("CERTBOT_EMAIL", "")

RECORD_TYPES = ["A", "AAAA"]

# ------------------------------
# LOGGING
# ------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    handlers=[
        logging.FileHandler("dns_bot.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("DNS-BOT")

# ------------------------------
# FLASK
# ------------------------------
web_app = Flask(__name__)
web_app.secret_key = os.getenv("FLASK_SECRET_KEY", uuid.uuid4().hex)

# ======================================================
# DATABASE
# ======================================================
class MySQLManager:
    def __init__(self):
        self.connection = None
        self.connect()
        self.init_database()

    def connect(self):
        self.connection = mysql.connector.connect(
            host=MYSQL_HOST,
            port=MYSQL_PORT,
            user=MYSQL_USER,
            password=MYSQL_PASSWORD,
            database=MYSQL_DATABASE
        )
        logger.info("✅ MySQL verbunden")

    def execute(self, query: str, params: tuple = (), fetch=False):
        cursor = self.connection.cursor(dictionary=True)
        cursor.execute(query, params)
        result = cursor.fetchall() if fetch else None
        self.connection.commit()
        cursor.close()
        return result

    def init_database(self):
        self.execute("""
        CREATE TABLE IF NOT EXISTS dns_records (
            id VARCHAR(255) PRIMARY KEY,
            name VARCHAR(255),
            type VARCHAR(10),
            content TEXT,
            ttl INT,
            proxied BOOLEAN,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        )""")

        self.execute("""
        CREATE TABLE IF NOT EXISTS ip_history (
            id INT AUTO_INCREMENT PRIMARY KEY,
            record_id VARCHAR(255),
            old_ip VARCHAR(45),
            new_ip VARCHAR(45),
            change_type VARCHAR(20),
            changed_by VARCHAR(255),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )""")

        self.execute("""
        CREATE TABLE IF NOT EXISTS system_logs (
            id INT AUTO_INCREMENT PRIMARY KEY,
            level VARCHAR(20),
            message TEXT,
            source VARCHAR(50),
            user_id VARCHAR(255),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )""")

    def log(self, level, message, source="SYSTEM", user_id=None):
        self.execute(
            "INSERT INTO system_logs (level, message, source, user_id) VALUES (%s,%s,%s,%s)",
            (level, message, source, user_id)
        )

# ======================================================
# PORT MANAGER
# ======================================================
class PortManager:
    def __init__(self, db: MySQLManager):
        self.db = db
        self.upnp = miniupnpc.UPnP()
        self.upnp.discoverdelay = 200

    def open_ports(self, ports: List[int]):
        try:
            self.upnp.discover()
            self.upnp.selectigd()
            for port in ports:
                self.upnp.addportmapping(
                    port, "TCP", self.upnp.lanaddr, port,
                    f"DNS-Bot {port}", ""
                )
            return True
        except Exception as e:
            self.db.log("ERROR", str(e), "UPNP")
            return False

# ======================================================
# CLOUDFLARE
# ======================================================
class CloudflareAPI:
    def __init__(self, db: MySQLManager):
        self.db = db
        self.base = f"https://api.cloudflare.com/client/v4/zones/{ZONE_ID}/dns_records"
        self.headers = {
            "Authorization": f"Bearer {CLOUDFLARE_API_TOKEN}",
            "Content-Type": "application/json"
        }

    def get_records(self):
        r = requests.get(self.base, headers=self.headers, timeout=10).json()
        return [x for x in r.get("result", []) if x["type"] in RECORD_TYPES]

    def update_record(self, rid, data, mode, user):
        url = f"{self.base}/{rid}"
        r = requests.put(url, headers=self.headers, json=data, timeout=10).json()
        if r.get("success"):
            self.db.log("INFO", f"{data['name']} updated", mode, user)
            return True
        return False

# ======================================================
# IP
# ======================================================
class IPManager:
    @staticmethod
    def get(v6=False):
        try:
            url = "https://api64.ipify.org" if v6 else "https://api.ipify.org"
            return requests.get(url, timeout=10).text.strip()
        except:
            return None

# ======================================================
# BOT
# ======================================================
class DNSBot(commands.Bot):
    def __init__(self):
        super().__init__(command_prefix="!", intents=discord.Intents.default())
        self.db = MySQLManager()
        self.cf = CloudflareAPI(self.db)
        self.ip = IPManager()
        self.ports = PortManager(self.db)

    async def setup_hook(self):
        await self.tree.sync()

bot = DNSBot()

# ======================================================
# AUTO UPDATE
# ======================================================
@tasks.loop(minutes=AUTO_UPDATE_INTERVAL_MIN)
async def auto_update():
    records = bot.cf.get_records()
    ipv4 = bot.ip.get(False)
    ipv6 = bot.ip.get(True)

    for r in records:
        ip = ipv6 if r["type"] == "AAAA" else ipv4
        if ip and r["content"] != ip:
            bot.cf.update_record(
                r["id"],
                {"type": r["type"], "name": r["name"], "content": ip, "ttl": 120, "proxied": r["proxied"]},
                "AUTO",
                "SYSTEM"
            )

# ======================================================
# START
# ======================================================
@bot.event
async def on_ready():
    bot.ports.open_ports([WEB_PORT, 80, 443])
    auto_update.start()
    logger.info("🚀 Bot gestartet")

if __name__ == "__main__":
    bot.run(DISCORD_BOT_TOKEN)
