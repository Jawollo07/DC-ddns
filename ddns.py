import discord 
from discord.ext import commands, tasks
from discord import app_commands
import requests
import subprocess
import os
import logging
from datetime import datetime
from dotenv import load_dotenv
from typing import List, Optional, Dict, Any
from flask import Flask, render_template, request, jsonify, session
import threading
import asyncio
import mysql.connector
from mysql.connector import Error
import json
import miniupnpc  # Neu hinzufügen

# 🌐 .env laden
load_dotenv()

# 🔧 Konfiguration
CLOUDFLARE_API_TOKEN = os.getenv("CF_API_TOKEN")
ZONE_ID = os.getenv("CF_ZONE_ID")
DISCORD_BOT_TOKEN = os.getenv("DISCORD_BOT_TOKEN")
AUTO_UPDATE_INTERVAL_MIN = int(os.getenv("AUTO_UPDATE_INTERVAL", "10"))
ALLOWED_USER_IDS = [int(uid.strip()) for uid in os.getenv("ALLOWED_USER_IDS", "").split(",") if uid.strip()]
WEB_USERNAME = os.getenv("WEB_USERNAME", "admin")
WEB_PASSWORD = os.getenv("WEB_PASSWORD", "password")
WEB_PORT = int(os.getenv("WEB_PORT", "5000"))
WEB_HOST = os.getenv("WEB_HOST", "0.0.0.0")

# MySQL Konfiguration
MYSQL_HOST = os.getenv("MYSQL_HOST", "localhost")
MYSQL_PORT = int(os.getenv("MYSQL_PORT", "3306"))
MYSQL_USER = os.getenv("MYSQL_USER", "ddns_user")
MYSQL_PASSWORD = os.getenv("MYSQL_PASSWORD", "ddns_password")
MYSQL_DATABASE = os.getenv("MYSQL_DATABASE", "ddns_bot")

# 🌩️ Nur diese Typen werden berücksichtigt
RECORD_TYPES = ["A", "AAAA"]

# Zertifikatdaten
CERTBOT_DOMAINS = [domain.strip() for domain in os.getenv("CERTBOT_DOMAINS", "").split(",") if domain.strip()]
CERTBOT_EMAIL = os.getenv("CERTBOT_EMAIL", "")

# 📊 Logging einrichten
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('dns_bot.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Flask App für Web-Control-Panel
web_app = Flask(__name__)
web_app.secret_key = os.getenv("FLASK_SECRET_KEY", "your-secret-key-here")
class MySQLManager:
    """Klasse zur Handhabung der MySQL-Datenbank"""
    
    def __init__(self):
        self.host = MYSQL_HOST
        self.port = MYSQL_PORT
        self.user = MYSQL_USER
        self.password = MYSQL_PASSWORD
        self.database = MYSQL_DATABASE
        self.connection = None
        self.connect()
        self.init_database()
    
    def connect(self):
        """Stellt Verbindung zur MySQL-Datenbank her"""
        try:
            self.connection = mysql.connector.connect(
                host=self.host,
                port=self.port,
                user=self.user,
                password=self.password,
                database=self.database
            )
            logger.info("✅ Verbindung zur MySQL-Datenbank hergestellt")
        except Error as e:
            logger.error(f"❌ Fehler bei der Verbindung zur MySQL-Datenbank: {e}")
            raise
    
    def init_database(self):
        """Initialisiert die Datenbank mit benötigten Tabellen"""
        try:
            cursor = self.connection.cursor()
            
            # Tabelle für DNS-Records
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS dns_records (
                    id VARCHAR(255) PRIMARY KEY,
                    name VARCHAR(255) NOT NULL,
                    type VARCHAR(10) NOT NULL,
                    content TEXT NOT NULL,
                    ttl INT DEFAULT 120,
                    proxied BOOLEAN DEFAULT FALSE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    INDEX idx_name (name),
                    INDEX idx_type (type)
                )
            """)
            
            # Tabelle für IP-History
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS ip_history (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    record_id VARCHAR(255),
                    old_ip VARCHAR(45),
                    new_ip VARCHAR(45),
                    change_type ENUM('AUTO', 'MANUAL', 'WEB'),
                    changed_by VARCHAR(255) DEFAULT 'SYSTEM',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (record_id) REFERENCES dns_records(id) ON DELETE CASCADE,
                    INDEX idx_record_id (record_id),
                    INDEX idx_created_at (created_at)
                )
            """)
            
            # Tabelle für Bot-Statistiken
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS bot_stats (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    total_updates INT DEFAULT 0,
                    last_update TIMESTAMP NULL,
                    last_auto_update TIMESTAMP NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
                )
            """)
            
            # Tabelle für System-Logs
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS system_logs (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    level VARCHAR(20) NOT NULL,
                    message TEXT NOT NULL,
                    source VARCHAR(100) DEFAULT 'SYSTEM',
                    user_id VARCHAR(255) DEFAULT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    INDEX idx_level (level),
                    INDEX idx_created_at (created_at)
                )
            """)
            
            # Tabelle für Web-Sessions
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS web_sessions (
                    session_id VARCHAR(255) PRIMARY KEY,
                    user_id VARCHAR(255),
                    ip_address VARCHAR(45),
                    user_agent TEXT,
                    login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    is_active BOOLEAN DEFAULT TRUE,
                    INDEX idx_user_id (user_id),
                    INDEX idx_login_time (login_time)
                )
            """)
            
            # Initiale Bot-Statistik zeile einfügen
            cursor.execute("""
                INSERT IGNORE INTO bot_stats (id, total_updates) 
                VALUES (1, 0)
            """)
            
            # 🆕 BEREINIGUNG: Records ohne ID fixen
            cursor.execute("""
                UPDATE dns_records 
                SET id = CONCAT(name, '_', type, '_', UNIX_TIMESTAMP())
                WHERE id IS NULL OR id = ''
            """)
            fixed_count = cursor.rowcount
            if fixed_count > 0:
                logger.warning(f"⚠️ {fixed_count} Records ohne ID gefixt!")
            
            self.connection.commit()
            cursor.close()
            logger.info("✅ Datenbank-Tabellen initialisiert")
            
        except Error as e:
            logger.error(f"❌ Fehler beim Initialisieren der Datenbank: {e}")
            raise
    
    def execute_query(self, query: str, params: tuple = None):
        """Führt eine SQL-Query aus"""
        try:
            cursor = self.connection.cursor(dictionary=True)
            cursor.execute(query, params or ())
            
            if query.strip().upper().startswith('SELECT'):
                result = cursor.fetchall()
            else:
                self.connection.commit()
                result = cursor.lastrowid
            
            cursor.close()
            return result
            
        except Error as e:
            logger.error(f"❌ Datenbank-Fehler: {e}")
            if self.connection.is_connected():
                self.connection.rollback()
            raise
    
    def save_dns_record(self, record_data: Dict[str, Any]):
        """Speichert oder aktualisiert einen DNS-Record"""
        query = """
            INSERT INTO dns_records (id, name, type, content, ttl, proxied)
            VALUES (%s, %s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE
            name = VALUES(name), type = VALUES(type), content = VALUES(content),
            ttl = VALUES(ttl), proxied = VALUES(proxied), updated_at = CURRENT_TIMESTAMP
        """
        params = (
            record_data['id'],
            record_data['name'],
            record_data['type'],
            record_data['content'],
            record_data.get('ttl', 120),
            record_data.get('proxied', False)
        )
        self.execute_query(query, params)
    
    def get_all_dns_records(self) -> List[Dict[str, Any]]:
        """Holt alle DNS-Records aus der Datenbank"""
        query = "SELECT * FROM dns_records ORDER BY name, type"
        return self.execute_query(query)
    
    def get_dns_record_by_id(self, record_id: str) -> Optional[Dict[str, Any]]:
        """Holt einen DNS-Record nach ID"""
        query = "SELECT * FROM dns_records WHERE id = %s"
        result = self.execute_query(query, (record_id,))
        return result[0] if result else None
    
    def log_ip_change(self, record_id: str, old_ip: str, new_ip: str, change_type: str, changed_by: str = "SYSTEM"):
        """Loggt IP-Änderungen"""
        query = """
            INSERT INTO ip_history (record_id, old_ip, new_ip, change_type, changed_by)
            VALUES (%s, %s, %s, %s, %s)
        """
        params = (record_id, old_ip, new_ip, change_type, changed_by)
        self.execute_query(query, params)
    
    def update_bot_stats(self, updates_count: int = 0, is_auto_update: bool = False):
        """Aktualisiert Bot-Statistiken"""
        if is_auto_update:
            query = """
                UPDATE bot_stats 
                SET total_updates = total_updates + %s,
                    last_auto_update = CURRENT_TIMESTAMP,
                    last_update = CURRENT_TIMESTAMP
                WHERE id = 1
            """
        else:
            query = """
                UPDATE bot_stats 
                SET total_updates = total_updates + %s,
                    last_update = CURRENT_TIMESTAMP
                WHERE id = 1
            """
        self.execute_query(query, (updates_count,))
    
    def get_bot_stats(self) -> Dict[str, Any]:
        """Holt Bot-Statistiken"""
        query = "SELECT * FROM bot_stats WHERE id = 1"
        result = self.execute_query(query)
        return result[0] if result else {}
    
    def log_system_event(self, level: str, message: str, source: str = "SYSTEM", user_id: str = None):
        """Loggt System-Ereignisse"""
        query = """
            INSERT INTO system_logs (level, message, source, user_id)
            VALUES (%s, %s, %s, %s)
        """
        params = (level, message, source, user_id)
        self.execute_query(query, params)
    
    def save_web_session(self, session_id: str, user_id: str, ip_address: str, user_agent: str):
        """Speichert Web-Session"""
        query = """
            INSERT INTO web_sessions (session_id, user_id, ip_address, user_agent)
            VALUES (%s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE
            last_activity = CURRENT_TIMESTAMP, is_active = TRUE
        """
        params = (session_id, user_id, ip_address, user_agent)
        self.execute_query(query, params)
    
    def cleanup_old_sessions(self, hours: int = 24):
        """Bereinigt alte Sessions"""
        query = "DELETE FROM web_sessions WHERE last_activity < DATE_SUB(NOW(), INTERVAL %s HOUR)"
        self.execute_query(query, (hours,))
    
    def get_recent_logs(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Holt recent system logs"""
        query = "SELECT * FROM system_logs ORDER BY created_at DESC LIMIT %s"
        return self.execute_query(query, (limit,))

class CloudflareAPI:
    """Klasse zur Handhabung der Cloudflare API Interaktionen"""
    
    def __init__(self, api_token: str, zone_id: str, db: MySQLManager):
        self.api_token = api_token
        self.zone_id = zone_id
        self.db = db
        self.base_url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records"
        self.headers = {
            "Authorization": f"Bearer {api_token}",
            "Content-Type": "application/json"
        }
    
    def get_all_dns_records(self) -> List[Dict[str, Any]]:
        """Holt alle DNS-Records mit Paginierung und speichert sie in der DB"""
        records = []
        page = 1
        per_page = 100
        
        while True:
            try:
                url = f"{self.base_url}?page={page}&per_page={per_page}"
                response = requests.get(url, headers=self.headers, timeout=10)
                response.raise_for_status()
                
                data = response.json()
                if not data.get("success"):
                    logger.error(f"Cloudflare API Error: {data.get('errors', 'Unknown error')}")
                    break
                
                records.extend(data["result"])
                
                # Speichere Records in der Datenbank
                for record in data["result"]:
                    if record["type"] in RECORD_TYPES:
                        self.db.save_dns_record(record)
                
                # Prüfe ob weitere Seiten vorhanden sind
                result_info = data["result_info"]
                if page * per_page >= result_info["total_count"]:
                    break
                page += 1
                
            except requests.exceptions.RequestException as e:
                logger.error(f"Fehler beim Abrufen der DNS-Records: {e}")
                break
        
        # Filtere nur die gewünschten Record-Typen
        return [r for r in records if r["type"] in RECORD_TYPES]
    
    def update_dns_record(self, record_id: str, record_data: Dict[str, Any], change_type: str = "MANUAL", changed_by: str = "SYSTEM") -> bool:
        """Aktualisiert einen DNS-Record und loggt die Änderung"""
        # 🆕 SCHUTZ VOR FALSCHER ID
        if not record_id or record_id == "AUTO_UPDATE":
            logger.error(f"❌ UNGÜLTIGE Record ID: {record_id}")
            return False
        
        try:
            # Hole alten Record aus der Datenbank
            old_record = self.db.get_dns_record_by_id(record_id)
            old_ip = old_record['content'] if old_record else None
            
            url = f"{self.base_url}/{record_id}"
            response = requests.put(url, headers=self.headers, json=record_data, timeout=10)
            response.raise_for_status()
            
            data = response.json()
            if data.get("success"):
                # 🆕 FIX: Füge ID zu record_data für DB-Save hinzu
                record_data['id'] = record_id
                
                # Speichere aktualisierten Record in der Datenbank
                self.db.save_dns_record(record_data)
                
                # Logge IP-Änderung
                if old_ip and old_ip != record_data['content']:
                    self.db.log_ip_change(record_id, old_ip, record_data['content'], change_type, changed_by)
                
                return True
            else:
                logger.error(f"Cloudflare API Error: {data.get('errors', 'Unknown error')}")
                return False
                
        except requests.exceptions.RequestException as e:
            logger.error(f"Fehler beim Aktualisieren des DNS-Records: {e}")
            return False

    def get_dns_record_by_name(self, name: str) -> Optional[Dict[str, Any]]:
        """Holt einen spezifischen DNS-Record nach Namen"""
        try:
            url = f"{self.base_url}?name={name}"
            response = requests.get(url, headers=self.headers, timeout=10)
            response.raise_for_status()
            
            data = response.json()
            if data.get("success") and data["result"]:
                record = data["result"][0]
                # Speichere in der Datenbank
                self.db.save_dns_record(record)
                return record
            return None
                
        except requests.exceptions.RequestException as e:
            logger.error(f"Fehler beim Abrufen des DNS-Records {name}: {e}")
            return None

class IPManager:
    """Klasse zur Handhabung von IP-Adressen"""
    
    @staticmethod
    def get_public_ip(v6: bool = False) -> Optional[str]:
        """Ermittelt die öffentliche IP-Adresse"""
        try:
            url = "https://api64.ipify.org" if v6 else "https://api.ipify.org"
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            ip = response.text.strip()
            logger.info(f"Öffentliche {'IPv6' if v6 else 'IPv4'} ermittelt: {ip}")
            return ip
        except Exception as e:
            logger.error(f"Fehler beim Ermitteln der IP: {e}")
            return None

    @staticmethod
    def get_client_ip(request) -> str:
        """Ermittelt die IP-Adresse des Clients"""
        if request.headers.get('X-Forwarded-For'):
            return request.headers['X-Forwarded-For'].split(',')[0]
        elif request.headers.get('X-Real-IP'):
            return request.headers['X-Real-IP']
        else:
            return request.remote_addr

class CertbotManager:
    """Klasse zur Handhabung von Certbot-Zertifikaten"""
    
    def __init__(self, domains: List[str], email: str, db: MySQLManager):
        self.domains = domains
        self.email = email
        self.db = db
    
    def renew_certificates(self) -> str:
        """Erneuert die SSL-Zertifikate"""
        if not self.domains or not self.email:
            return "⚠️ Keine Zertifikatsdaten konfiguriert."
        
        try:
            cmd = [
                "sudo", "certbot", "certonly", "--standalone",
                "--agree-tos", "--non-interactive", "--expand",
                "--email", self.email
            ]
            
            for domain in self.domains:
                cmd += ["-d", domain]
            
            logger.info(f"Certbot-Befehl: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                logger.info("Certbot-Zertifikate erfolgreich erneuert")
                self.db.log_system_event("INFO", "Certbot-Zertifikate erfolgreich erneuert", "CERTBOT")
                return "✅ Certbot-Zertifikate wurden erfolgreich erneuert."
            else:
                error_msg = f"❌ Certbot-Fehler (Code {result.returncode}):\n{result.stderr}"
                logger.error(error_msg)
                self.db.log_system_event("ERROR", f"Certbot-Fehler: {result.stderr}", "CERTBOT")
                return error_msg
                
        except subprocess.TimeoutExpired:
            error_msg = "❌ Certbot-Prozess timeout"
            logger.error(error_msg)
            self.db.log_system_event("ERROR", "Certbot-Prozess timeout", "CERTBOT")
            return error_msg
        except Exception as e:
            error_msg = f"❌ Certbot-Ausnahme: {str(e)}"
            logger.error(error_msg)
            self.db.log_system_event("ERROR", f"Certbot-Ausnahme: {str(e)}", "CERTBOT")
            return error_msg

class PortManager:
    """Klasse zur Handhabung von UPnP Portfreigaben"""
    
    def __init__(self, db: MySQLManager):
        self.db = db
        self.upnp = miniupnpc.UPnP()
        self.upnp.discoverdelay = 200
        self.active_ports = []

    def open_ports(self, tcp_ports: List[int] = [], udp_ports: List[int] = []) -> Dict[str, Any]:
        """Versucht, eine Liste von Ports am Router zu öffnen"""
        results = {"success": [], "error": []}
        
        try:
            self.upnp.discover()
            self.upnp.selectigd()
            
            # TCP Ports
            for port in tcp_ports:
                try:
                    # addportmapping(port, protocol, internal_client, internal_port, description, remote_host)
                    self.upnp.addportmapping(port, 'TCP', self.upnp.lanaddr, port, f'DNS-Bot TCP {port}', '')
                    results["success"].append(f"TCP {port}")
                    self.db.log_system_event("INFO", f"Port TCP {port} via UPnP geöffnet", "PORT_MANAGER")
                except Exception as e:
                    results["error"].append(f"TCP {port}: {str(e)}")

            # UDP Ports
            for port in udp_ports:
                try:
                    self.upnp.addportmapping(port, 'UDP', self.upnp.lanaddr, port, f'DNS-Bot UDP {port}', '')
                    results["success"].append(f"UDP {port}")
                    self.db.log_system_event("INFO", f"Port UDP {port} via UPnP geöffnet", "PORT_MANAGER")
                except Exception as e:
                    results["error"].append(f"UDP {port}: {str(e)}")
            
            return results
        except Exception as e:
            logger.error(f"UPnP Fehler: {e}")
            return {"error": [str(e)], "success": []}

    def get_active_mappings(self):
        """Listet alle aktiven Freigaben auf dem Router (UPnP)"""
        mappings = []
        try:
            self.upnp.discover()
            self.upnp.selectigd()
            i = 0
            while True:
                p = self.upnp.getgenericportmapping(i)
                if p is None:
                    break
                mappings.append(p)
                i += 1
            return mappings
        except:
            return []

class DNSBot(commands.Bot):
    """Hauptklasse des DNS-Bots"""
    
    def __init__(self):
        intents = discord.Intents.default()
        super().__init__(command_prefix="!", intents=intents)
        
        # MySQL Manager initialisieren
        self.db = MySQLManager()
        
        # Manager initialisieren
        self.cf_api = CloudflareAPI(CLOUDFLARE_API_TOKEN, ZONE_ID, self.db)
        self.ip_manager = IPManager()
        self.certbot_manager = CertbotManager(CERTBOT_DOMAINS, CERTBOT_EMAIL, self.db)
        self.port_manager = PortManager(self.db)
        # Status-Variablen
        self.last_update = None
        self.update_count = 0
        self.web_interface = None
    async def setup_hook(self):
        """Wird beim Start des Bots aufgerufen"""
        await self.tree.sync()
        logger.info("Slash-Befehle synchronisiert")
        self.db.log_system_event("INFO", "Discord Bot gestartet und Befehle synchronisiert", "DISCORD_BOT")
    
    def is_authorized(self, user_id: int) -> bool:
        """Prüft ob Benutzer berechtigt ist"""
        return user_id in ALLOWED_USER_IDS

    def start_web_interface(self):
        """Startet das Web-Interface in einem separaten Thread"""
        self.web_interface = WebInterface(self, self.cf_api, self.ip_manager, self.db)
        self.web_interface.start()

# Bot initialisieren
bot = DNSBot()

class WebInterface:
    """Web-Control-Panel für DNS-Management"""
    
    def __init__(self, bot: DNSBot, cf_api: CloudflareAPI, ip_manager: IPManager, db: MySQLManager):
        self.bot = bot
        self.cf_api = cf_api
        self.ip_manager = ip_manager
        self.db = db
        self.app = web_app
        self.setup_routes()
    
    def setup_routes(self):
        """Definiert die Web-Routen"""
        # In WebInterface.setup_routes
        @self.app.route('/api/ports')
        def api_ports():
            if not session.get('logged_in'):
                return jsonify({'error': 'Nicht autorisiert'}), 401
    
            mappings = self.bot.port_manager.get_active_mappings()
            return jsonify(mappings)
        @self.app.route('/')
        def index():
            if not session.get('logged_in'):
                return render_template('login.html')
            return render_template('index.html')
        
        @self.app.route('/login', methods=['POST'])
        def login():
            username = request.form.get('username')
            password = request.form.get('password')
            
            if username == WEB_USERNAME and password == WEB_PASSWORD:
                session['logged_in'] = True
                # Logge Login in Datenbank
                self.db.save_web_session(
                    session_id=session.sid,
                    user_id=username,
                    ip_address=self.ip_manager.get_client_ip(request),
                    user_agent=request.headers.get('User-Agent', '')
                )
                self.db.log_system_event("INFO", f"Web-Login von {username}", "WEB_INTERFACE", username)
                return jsonify({'success': True})
            return jsonify({'success': False, 'error': 'Ungültige Anmeldedaten'})
        
        @self.app.route('/logout')
        def logout():
            if session.get('logged_in'):
                self.db.log_system_event("INFO", "Web-Logout", "WEB_INTERFACE", session.get('user_id', 'unknown'))
            session.pop('logged_in', None)
            return jsonify({'success': True})
        
        @self.app.route('/api/status')
        def api_status():
            if not session.get('logged_in'):
                return jsonify({'error': 'Nicht autorisiert'}), 401
            
            try:
                # Aktualisiere Records von Cloudflare
                records = self.cf_api.get_all_dns_records()
                ipv4 = self.ip_manager.get_public_ip(False)
                ipv6 = self.ip_manager.get_public_ip(True)
                client_ip = self.ip_manager.get_client_ip(request)
                bot_stats = self.db.get_bot_stats()
                
                status_data = {
                    'records': records,
                    'ips': {
                        'ipv4': ipv4,
                        'ipv6': ipv6,
                        'client_ip': client_ip
                    },
                    'bot_status': {
                        'last_update': bot_stats.get('last_update'),
                        'last_auto_update': bot_stats.get('last_auto_update'),
                        'total_updates': bot_stats.get('total_updates', 0)
                    }
                }
                return jsonify(status_data)
            except Exception as e:
                logger.error(f"Fehler in API Status: {e}")
                self.db.log_system_event("ERROR", f"API Status Fehler: {str(e)}", "WEB_INTERFACE")
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/update', methods=['POST'])
        def api_update():
            if not session.get('logged_in'):
                return jsonify({'error': 'Nicht autorisiert'}), 401
            
            try:
                data = request.get_json()
                record_name = data.get('record_name')
                ipv4 = data.get('ipv4')
                ipv6 = data.get('ipv6')
                use_auto_ip = data.get('use_auto_ip', True)
                
                # Wenn use_auto_ip True ist, verwende automatische IPs
                if use_auto_ip:
                    auto_ipv4 = self.ip_manager.get_public_ip(False)
                    auto_ipv6 = self.ip_manager.get_public_ip(True)
                    ipv4 = ipv4 or auto_ipv4
                    ipv6 = ipv6 or auto_ipv6
                
                records = self.cf_api.get_all_dns_records()
                results = []
                updated_count = 0
                
                for record in records:
                    # Filtere nach Record-Name falls angegeben
                    if record_name and record['name'] != record_name:
                        continue
                    
                    if record["type"] == "A" and ipv4 and record["content"] != ipv4:
                        record_data = {
                            "type": record["type"],
                            "name": record["name"],
                            "content": ipv4,
                            "ttl": 120,
                            "proxied": record.get("proxied", False)
                        }
                        
                        if self.cf_api.update_dns_record(record["id"], record_data, "WEB", session.get('user_id', 'web_user')):
                            results.append(f"✅ {record['type']} {record['name']}: {ipv4}")
                            updated_count += 1
                        else:
                            results.append(f"❌ Fehler bei {record['type']} {record['name']}")
                    
                    elif record["type"] == "AAAA" and ipv6 and record["content"] != ipv6:
                        record_data = {
                            "type": record["type"],
                            "name": record["name"],
                            "content": ipv6,
                            "ttl": 120,
                            "proxied": record.get("proxied", False)
                        }
                        
                        if self.cf_api.update_dns_record(record["id"], record_data, "WEB", session.get('user_id', 'web_user')):
                            results.append(f"✅ {record['type']} {record['name']}: {ipv6}")
                            updated_count += 1
                        else:
                            results.append(f"❌ Fehler bei {record['type']} {record['name']}")
                
                # Update Bot-Statistiken
                if updated_count > 0:
                    self.db.update_bot_stats(updated_count)
                
                self.db.log_system_event("INFO", f"Web-Update: {updated_count} Records aktualisiert", "WEB_INTERFACE", session.get('user_id', 'web_user'))
                
                return jsonify({
                    'success': True,
                    'updated_count': updated_count,
                    'results': results,
                    'timestamp': datetime.now().isoformat()
                })
                
            except Exception as e:
                logger.error(f"Fehler in API Update: {e}")
                self.db.log_system_event("ERROR", f"API Update Fehler: {str(e)}", "WEB_INTERFACE", session.get('user_id', 'web_user'))
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/renew-cert', methods=['POST'])
        def api_renew_cert():
            if not session.get('logged_in'):
                return jsonify({'error': 'Nicht autorisiert'}), 401
            
            try:
                result = self.bot.certbot_manager.renew_certificates()
                return jsonify({'success': True, 'result': result})
            except Exception as e:
                logger.error(f"Fehler in API Renew Cert: {e}")
                self.db.log_system_event("ERROR", f"API Renew Cert Fehler: {str(e)}", "WEB_INTERFACE", session.get('user_id', 'web_user'))
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/history')
        def api_history():
            if not session.get('logged_in'):
                return jsonify({'error': 'Nicht autorisiert'}), 401
            
            try:
                limit = request.args.get('limit', 50, type=int)
                history = self.db.execute_query("""
                    SELECT h.*, r.name as record_name 
                    FROM ip_history h 
                    LEFT JOIN dns_records r ON h.record_id = r.id 
                    ORDER BY h.created_at DESC 
                    LIMIT %s
                """, (limit,))
                return jsonify(history)
            except Exception as e:
                logger.error(f"Fehler in API History: {e}")
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/logs')
        def api_logs():
            if not session.get('logged_in'):
                return jsonify({'error': 'Nicht autorisiert'}), 401
            
            try:
                limit = request.args.get('limit', 100, type=int)
                logs = self.db.get_recent_logs(limit)
                return jsonify(logs)
            except Exception as e:
                logger.error(f"Fehler in API Logs: {e}")
                return jsonify({'error': str(e)}), 500
    
    def start(self):
        """Startet den Web-Server in einem separaten Thread"""
        def run_flask():
            self.app.run(
                host=WEB_HOST,
                port=WEB_PORT,
                debug=False,
                use_reloader=False
            )
        
        flask_thread = threading.Thread(target=run_flask, daemon=True)
        flask_thread.start()
logger.info(f"🌐 Web-Control-Panel gestartet auf http://{WEB_HOST}:{WEB_PORT}")
self.db.log_system_event("INFO", f"Web-Control-Panel gestartet auf Port {WEB_PORT}", "WEB_INTERFACE")
@bot.event
async def on_ready():
    """Wird aufgerufen wenn der Bot bereit ist"""
    logger.info(f"✅ Bot bereit als {bot.user}")
    needed_tcp = [WEB_PORT, 80, 443] 
    res = bot.port_manager.open_ports(tcp_ports=needed_tcp)
    logger.info(f"Ports Status: {res}")
    # ------------------------------------
    logger.info(f"🔧 Starte Web-Control-Panel...")
    bot.start_web_interface()
    auto_update_loop.start()
    # Starte Session-Cleanup Task
    session_cleanup_loop.start()

@bot.event
async def on_command(ctx):
    """Wird aufgerufen wenn ein Befehl ausgeführt wird"""
    bot.db.log_system_event("INFO", f"Discord Befehl ausgeführt: {ctx.command}", "DISCORD_BOT", str(ctx.author.id))

# 🔁 Auto-Update Loop - ULTRA-GEFIXT
@tasks.loop(minutes=AUTO_UPDATE_INTERVAL_MIN)
async def auto_update_loop():
    """Automatische DNS-Aktualisierung - ULTRA-GEFIXT"""
    logger.info(f"🔁 Auto-Update gestartet (Intervall: {AUTO_UPDATE_INTERVAL_MIN}min)")
    
    try:
        # 1️⃣ HOL ECHTE RECORDS DIREKT VON CLOUDFLARE
        records = bot.cf_api.get_all_dns_records()
        ipv4 = bot.ip_manager.get_public_ip(False)
        ipv6 = bot.ip_manager.get_public_ip(True)
        
        logger.info(f"📋 {len(records)} Records gefunden | IPv4: {ipv4} | IPv6: {ipv6}")
        
        if not records:
            logger.warning("⚠️ Keine DNS-Records gefunden")
            return
            
        update_count = 0
        update_messages = []
        
        for i, record in enumerate(records):
            # 2️⃣ DEBUG: JEDEN Record ausgeben
            logger.info(f"Record {i+1}: name='{record.get('name')}' type='{record.get('type')}' id='{record.get('id')}' content='{record.get('content')}'")
            
            # 3️⃣ HARTE ID-VALIDIERUNG
            record_id = record.get('id')
            if not record_id or record_id == '' or record_id is None:
                logger.error(f"❌ Record {i+1} OHNE ID: {record.get('name')} - SKIP!")
                continue
            
            # 4️⃣ IP-Vergleich
            ip = ipv6 if record["type"] == "AAAA" else ipv4
            if ip and record["content"] != ip:
                record_data = {
                    "type": record["type"],
                    "name": record["name"],
                    "content": ip,
                    "ttl": 120,
                    "proxied": record.get("proxied", False)
                }
                
                logger.info(f"🔄 Update {record['name']} (ID: {record_id}) → {ip}")
                
                if bot.cf_api.update_dns_record(record_id, record_data, "AUTO", "AUTO_UPDATE"):
                    update_count += 1
                    update_messages.append(f"✅ {record['name']} → {ip}")
                    logger.info(f"✅ SUCCESS {record['name']} (ID: {record_id})")
                else:
                    update_messages.append(f"❌ {record['name']}")
                    logger.error(f"❌ FAILED {record['name']} (ID: {record_id})")
            else:
                logger.debug(f"⏭️ {record['name']}: OK")
        
        # 5️⃣ STATISTIK
        if update_count > 0:
            bot.db.update_bot_stats(update_count, is_auto_update=True)
            logger.info(f"🎉 Auto-Update: {update_count}/{len(records)} Records aktualisiert")
        else:
            logger.info("ℹ️ Auto-Update: Alle Records aktuell")
        
        bot.last_update = datetime.now()
        bot.update_count += update_count
        
        # 6️⃣ LOG
        bot.db.log_system_event(
            "INFO", 
            f"Auto-Update: {update_count} von {len(records)} aktualisiert\n" + 
            "\n".join(update_messages[:5]),  # Max 5 Nachrichten
            "AUTO_UPDATE"
        )
        
    except Exception as e:
        error_msg = f"Auto-Update FEHLER: {str(e)}"
        logger.error(error_msg)
        bot.db.log_system_event("ERROR", error_msg, "AUTO_UPDATE")

# 🧹 Session-Cleanup Loop
@tasks.loop(hours=24)
async def session_cleanup_loop():
    """Bereinigt alte Web-Sessions"""
    try:
        bot.db.cleanup_old_sessions(24)
        logger.info("Alte Web-Sessions bereinigt")
    except Exception as e:
        logger.error(f"Fehler beim Bereinigen der Sessions: {e}")

@bot.tree.command(name="update", description="DNS-Einträge manuell aktualisieren")
@app_commands.describe(ipv4="IPv4 manuell setzen", ipv6="IPv6 manuell setzen")
async def update(interaction: discord.Interaction, ipv4: str = None, ipv6: str = None):
    """Manuelle DNS-Aktualisierung"""
    if not bot.is_authorized(interaction.user.id):
        await interaction.response.send_message("🚫 Keine Berechtigung.", ephemeral=True)
        return
    
    await interaction.response.defer()
    
    try:
        records = bot.cf_api.get_all_dns_records()
        messages = []
        updated_count = 0
        
        for record in records:
            if record["type"] == "A":
                ip = ipv4 if ipv4 else bot.ip_manager.get_public_ip(False)
            elif record["type"] == "AAAA":
                ip = ipv6 if ipv6 else bot.ip_manager.get_public_ip(True)
            else:
                continue
            
            if ip and record["content"] != ip:
                record_data = {
                    "type": record["type"],
                    "name": record["name"],
                    "content": ip,
                    "ttl": 120,
                    "proxied": record.get("proxied", False)
                }
                
                if bot.cf_api.update_dns_record(record["id"], record_data, "MANUAL", str(interaction.user.id)):
                    messages.append(f"✅ {record['type']} {record['name']}: `{ip}`")
                    updated_count += 1
                else:
                    messages.append(f"❌ Fehler bei {record['type']} {record['name']}")
            else:
                messages.append(f"⏭️ {record['type']} {record['name']}: Keine Änderung notwendig")
        
        # Update Bot-Statistiken
        if updated_count > 0:
            bot.db.update_bot_stats(updated_count)
        
        bot.last_update = datetime.now()
        bot.update_count += updated_count
        
        embed = discord.Embed(
            title="DNS Update abgeschlossen",
            description=f"**{updated_count} Records aktualisiert**\n\n" + "\n".join(messages),
            color=discord.Color.green() if updated_count > 0 else discord.Color.blue(),
            timestamp=datetime.now()
        )
        await interaction.followup.send(embed=embed)
        
    except Exception as e:
        logger.error(f"Fehler beim manuellen Update: {e}")
        bot.db.log_system_event("ERROR", f"Manueller Update Fehler: {str(e)}", "DISCORD_BOT", str(interaction.user.id))
        await interaction.followup.send("❌ Ein Fehler ist beim Update aufgetreten.")

@bot.tree.command(name="status", description="Zeigt den DNS- und IP-Status")
async def status(interaction: discord.Interaction):
    """Zeigt den aktuellen Status"""
    if not bot.is_authorized(interaction.user.id):
        await interaction.response.send_message("🚫 Keine Berechtigung.", ephemeral=True)
        return
    
    await interaction.response.defer()
    
    try:
        records = bot.cf_api.get_all_dns_records()
        ipv4 = bot.ip_manager.get_public_ip(False)
        ipv6 = bot.ip_manager.get_public_ip(True)
        bot_stats = bot.db.get_bot_stats()
        
        embed = discord.Embed(
            title="📊 DNS Status Report",
            color=discord.Color.blue(),
            timestamp=datetime.now()
        )
        
        # Bot-Statistiken
        if bot_stats.get('last_update'):
            embed.add_field(
                name="Bot-Statistiken",
                value=f"Letztes Update: {bot_stats['last_update'].strftime('%d.%m.%Y %H:%M')}\n"
                      f"Gesamtaktualisierungen: {bot_stats.get('total_updates', 0)}",
                inline=False
            )
        
        # IP-Status
        embed.add_field(
            name="🌐 Aktuelle IPs",
            value=f"IPv4: `{ipv4 or 'N/A'}`\nIPv6: `{ipv6 or 'N/A'}`",
            inline=False
        )
        
        # DNS-Records
        for record in records[:10]:  # Begrenze auf 10 Records um Embed-Limit nicht zu überschreiten
            public_ip = ipv6 if record["type"] == "AAAA" else ipv4
            status_icon = "✅" if record["content"] == public_ip else "⚠️"
            
            embed.add_field(
                name=f"{record['type']} {record['name']} {status_icon}",
                value=f"DNS: `{record['content']}`\n"
                      f"Aktuell: `{public_ip or 'N/A'}`\n"
                      f"Proxied: {record.get('proxied', False)}",
                inline=True
            )
        
        if len(records) > 10:
            embed.set_footer(text=f"Zeige 10 von {len(records)} Records")
        
        await interaction.followup.send(embed=embed)
        
    except Exception as e:
        logger.error(f"Fehler beim Status-Check: {e}")
        bot.db.log_system_event("ERROR", f"Status-Check Fehler: {str(e)}", "DISCORD_BOT", str(interaction.user.id))
        await interaction.followup.send("❌ Ein Fehler ist beim Status-Check aufgetreten.")

@bot.tree.command(name="renewcert", description="Erneuert das SSL-Zertifikat mit Certbot")
async def renewcert(interaction: discord.Interaction):
    """Erneuert SSL-Zertifikate"""
    if not bot.is_authorized(interaction.user.id):
        await interaction.response.send_message("🚫 Keine Berechtigung.", ephemeral=True)
        return
    
    await interaction.response.defer()
    
    try:
        result = bot.certbot_manager.renew_certificates()
        await interaction.followup.send(result)
    except Exception as e:
        logger.error(f"Fehler bei Zertifikatserneuerung: {e}")
        bot.db.log_system_event("ERROR", f"Zertifikatserneuerung Fehler: {str(e)}", "DISCORD_BOT", str(interaction.user.id))
        await interaction.followup.send("❌ Ein Fehler ist bei der Zertifikatserneuerung aufgetreten.")

@bot.tree.command(name="info", description="Zeigt Bot-Informationen")
async def info(interaction: discord.Interaction):
    """Zeigt Bot-Informationen"""
    bot_stats = bot.db.get_bot_stats()
    
    embed = discord.Embed(
        title="🤖 DNS Bot Information",
        description="Automatische DNS-Verwaltung mit Cloudflare Integration",
        color=discord.Color.gold(),
        timestamp=datetime.now()
    )
    
    embed.add_field(name="Version", value="3.0", inline=True)
    embed.add_field(name="Developer", value="Jawollo07", inline=True)
    embed.add_field(name="Source", value="[GitHub](https://github.com/Jawollo07/DC-ddns.git)", inline=True)
    embed.add_field(name="Befehle", value="/update, /status, /renewcert, /info", inline=False)
    embed.add_field(name="Auto-Update", value=f"Alle {AUTO_UPDATE_INTERVAL_MIN} Minuten", inline=True)
    embed.add_field(name="Überwachte Records", value=f"{', '.join(RECORD_TYPES)}", inline=True)
    embed.add_field(name="Web-Control-Panel", value=f"http://{WEB_HOST}:{WEB_PORT}", inline=True)
    embed.add_field(name="Gesamt-Updates", value=f"{bot_stats.get('total_updates', 0)}", inline=True)
    embed.add_field(name="Datenbank", value="MySQL", inline=True)
    
    await interaction.response.send_message(embed=embed)

@bot.tree.command(name="history", description="Zeigt die letzten IP-Änderungen")
@app_commands.describe(limit="Anzahl der Einträge (max. 20)")
async def history(interaction: discord.Interaction, limit: int = 10):
    """Zeigt IP-Änderungshistorie"""
    if not bot.is_authorized(interaction.user.id):
        await interaction.response.send_message("🚫 Keine Berechtigung.", ephemeral=True)
        return
    
    if limit > 20:
        limit = 20
    
    await interaction.response.defer()
    
    try:
        history = bot.db.execute_query("""
            SELECT h.*, r.name as record_name 
            FROM ip_history h 
            LEFT JOIN dns_records r ON h.record_id = r.id 
            ORDER BY h.created_at DESC 
            LIMIT %s
        """, (limit,))
        
        embed = discord.Embed(
            title="📋 IP-Änderungshistorie",
            color=discord.Color.purple(),
            timestamp=datetime.now()
        )
        
        for entry in history:
            embed.add_field(
                name=f"{entry['record_name']} ({entry['change_type']})",
                value=f"Von `{entry['old_ip']}` zu `{entry['new_ip']}`\n"
                      f"Von {entry['changed_by']} am {entry['created_at'].strftime('%d.%m.%Y %H:%M')}",
                inline=False
            )
        
        if not history:
            embed.description = "Keine IP-Änderungen gefunden."
        
        await interaction.followup.send(embed=embed)
        
    except Exception as e:
        logger.error(f"Fehler beim Abrufen der Historie: {e}")
        await interaction.followup.send("❌ Ein Fehler ist beim Abrufen der Historie aufgetreten.")

# Fehlerbehandlung
@bot.event
async def on_command_error(ctx, error):
    """Globale Fehlerbehandlung"""
    if isinstance(error, commands.CommandNotFound):
        return
    
    logger.error(f"Command Error: {error}")
    bot.db.log_system_event("ERROR", f"Discord Command Error: {str(error)}", "DISCORD_BOT", str(ctx.author.id))
    
    if isinstance(error, commands.CheckFailure):
        await ctx.send("🚫 Keine Berechtigung für diesen Befehl.", ephemeral=True)
    else:
        await ctx.send("❌ Ein unerwarteter Fehler ist aufgetreten.", ephemeral=True)

# 🔄 Auto-Update Loop Error Handling
@auto_update_loop.error
async def auto_update_loop_error(error):
    """Fehlerbehandlung für die Auto-Update Loop"""
    logger.error(f"Auto-Update Loop Error: {error}")
    bot.db.log_system_event("ERROR", f"Auto-Update Loop Error: {str(error)}", "AUTO_UPDATE")
    # Versuche die Loop nach einem Fehler neu zu starten
    await asyncio.sleep(60)
    auto_update_loop.restart()

# ▶️ Bot starten
if __name__ == "__main__":
    if not all([CLOUDFLARE_API_TOKEN, ZONE_ID, DISCORD_BOT_TOKEN]):
        logger.error("Fehlende Umgebungsvariablen! Bitte .env Datei überprüfen.")
        exit(1)
    
    logger.info("Starting DNS Bot with MySQL Database and Web Control Panel...")
    bot.run(DISCORD_BOT_TOKEN)