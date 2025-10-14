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

class CloudflareAPI:
    """Klasse zur Handhabung der Cloudflare API Interaktionen"""
    
    def __init__(self, api_token: str, zone_id: str):
        self.api_token = api_token
        self.zone_id = zone_id
        self.base_url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records"
        self.headers = {
            "Authorization": f"Bearer {api_token}",
            "Content-Type": "application/json"
        }
    
    def get_all_dns_records(self) -> List[Dict[str, Any]]:
        """Holt alle DNS-Records mit Paginierung"""
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
    
    def update_dns_record(self, record_id: str, record_data: Dict[str, Any]) -> bool:
        """Aktualisiert einen DNS-Record"""
        try:
            url = f"{self.base_url}/{record_id}"
            response = requests.put(url, headers=self.headers, json=record_data, timeout=10)
            response.raise_for_status()
            
            data = response.json()
            if data.get("success"):
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
                return data["result"][0]
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
    
    def __init__(self, domains: List[str], email: str):
        self.domains = domains
        self.email = email
    
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
                return "✅ Certbot-Zertifikate wurden erfolgreich erneuert."
            else:
                error_msg = f"❌ Certbot-Fehler (Code {result.returncode}):\n{result.stderr}"
                logger.error(error_msg)
                return error_msg
                
        except subprocess.TimeoutExpired:
            error_msg = "❌ Certbot-Prozess timeout"
            logger.error(error_msg)
            return error_msg
        except Exception as e:
            error_msg = f"❌ Certbot-Ausnahme: {str(e)}"
            logger.error(error_msg)
            return error_msg

class DNSBot(commands.Bot):
    """Hauptklasse des DNS-Bots"""
    
    def __init__(self):
        intents = discord.Intents.default()
        super().__init__(command_prefix="!", intents=intents)
        
        # Manager initialisieren
        self.cf_api = CloudflareAPI(CLOUDFLARE_API_TOKEN, ZONE_ID)
        self.ip_manager = IPManager()
        self.certbot_manager = CertbotManager(CERTBOT_DOMAINS, CERTBOT_EMAIL)
        
        # Status-Variablen
        self.last_update = None
        self.update_count = 0
        self.web_interface = None
    
    async def setup_hook(self):
        """Wird beim Start des Bots aufgerufen"""
        await self.tree.sync()
        logger.info("Slash-Befehle synchronisiert")
    
    def is_authorized(self, user_id: int) -> bool:
        """Prüft ob Benutzer berechtigt ist"""
        return user_id in ALLOWED_USER_IDS

    def start_web_interface(self):
        """Startet das Web-Interface in einem separaten Thread"""
        self.web_interface = WebInterface(self, self.cf_api, self.ip_manager)
        self.web_interface.start()

# Bot initialisieren
bot = DNSBot()

class WebInterface:
    """Web-Control-Panel für DNS-Management"""
    
    def __init__(self, bot: DNSBot, cf_api: CloudflareAPI, ip_manager: IPManager):
        self.bot = bot
        self.cf_api = cf_api
        self.ip_manager = ip_manager
        self.app = web_app
        self.setup_routes()
    
    def setup_routes(self):
        """Definiert die Web-Routen"""
        
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
                return jsonify({'success': True})
            return jsonify({'success': False, 'error': 'Ungültige Anmeldedaten'})
        
        @self.app.route('/logout')
        def logout():
            session.pop('logged_in', None)
            return jsonify({'success': True})
        
        @self.app.route('/api/status')
        def api_status():
            if not session.get('logged_in'):
                return jsonify({'error': 'Nicht autorisiert'}), 401
            
            try:
                records = self.cf_api.get_all_dns_records()
                ipv4 = self.ip_manager.get_public_ip(False)
                ipv6 = self.ip_manager.get_public_ip(True)
                client_ip = self.ip_manager.get_client_ip(request)
                
                status_data = {
                    'records': records,
                    'ips': {
                        'ipv4': ipv4,
                        'ipv6': ipv6,
                        'client_ip': client_ip
                    },
                    'bot_status': {
                        'last_update': self.bot.last_update.isoformat() if self.bot.last_update else None,
                        'update_count': self.bot.update_count
                    }
                }
                return jsonify(status_data)
            except Exception as e:
                logger.error(f"Fehler in API Status: {e}")
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
                        
                        if self.cf_api.update_dns_record(record["id"], record_data):
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
                        
                        if self.cf_api.update_dns_record(record["id"], record_data):
                            results.append(f"✅ {record['type']} {record['name']}: {ipv6}")
                            updated_count += 1
                        else:
                            results.append(f"❌ Fehler bei {record['type']} {record['name']}")
                
                self.bot.last_update = datetime.now()
                self.bot.update_count += updated_count
                
                return jsonify({
                    'success': True,
                    'updated_count': updated_count,
                    'results': results,
                    'timestamp': datetime.now().isoformat()
                })
                
            except Exception as e:
                logger.error(f"Fehler in API Update: {e}")
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

@bot.event
async def on_ready():
    """Wird aufgerufen wenn der Bot bereit ist"""
    logger.info(f"✅ Bot bereit als {bot.user}")
    logger.info(f"🔧 Starte Web-Control-Panel...")
    bot.start_web_interface()
    auto_update_loop.start()

# 🔁 Auto-Update Loop
@tasks.loop(minutes=AUTO_UPDATE_INTERVAL_MIN)
async def auto_update_loop():
    """Automatische DNS-Aktualisierung"""
    logger.info(f"🔁 Auto-Update gestartet (Intervall: {AUTO_UPDATE_INTERVAL_MIN}min)")
    
    try:
        records = bot.cf_api.get_all_dns_records()
        ipv4 = bot.ip_manager.get_public_ip(False)
        ipv6 = bot.ip_manager.get_public_ip(True)
        
        update_count = 0
        for record in records:
            ip = ipv6 if record["type"] == "AAAA" else ipv4
            if ip and record["content"] != ip:
                record_data = {
                    "type": record["type"],
                    "name": record["name"],
                    "content": ip,
                    "ttl": 120,
                    "proxied": record.get("proxied", False)
                }
                
                if bot.cf_api.update_dns_record(record["id"], record_data):
                    update_count += 1
                    logger.info(f"Record {record['name']} aktualisiert auf {ip}")
        
        bot.last_update = datetime.now()
        bot.update_count += update_count
        logger.info(f"Auto-Update abgeschlossen: {update_count} Records aktualisiert")
        
    except Exception as e:
        logger.error(f"Fehler in auto_update_loop: {e}")

# Die restlichen Discord-Befehle bleiben unverändert...
# (update, status, renewcert, info commands bleiben gleich wie im ursprünglichen Code)

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
                
                if bot.cf_api.update_dns_record(record["id"], record_data):
                    messages.append(f"✅ {record['type']} {record['name']}: `{ip}`")
                    updated_count += 1
                else:
                    messages.append(f"❌ Fehler bei {record['type']} {record['name']}")
            else:
                messages.append(f"⏭️ {record['type']} {record['name']}: Keine Änderung notwendig")
        
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
        
        embed = discord.Embed(
            title="📊 DNS Status Report",
            color=discord.Color.blue(),
            timestamp=datetime.now()
        )
        
        # Bot-Statistiken
        if bot.last_update:
            embed.add_field(
                name="Bot-Statistiken",
                value=f"Letztes Update: {bot.last_update.strftime('%d.%m.%Y %H:%M')}\n"
                      f"Gesamtaktualisierungen: {bot.update_count}",
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
        await interaction.followup.send("❌ Ein Fehler ist bei der Zertifikatserneuerung aufgetreten.")

@bot.tree.command(name="info", description="Zeigt Bot-Informationen")
async def info(interaction: discord.Interaction):
    """Zeigt Bot-Informationen"""
    embed = discord.Embed(
        title="🤖 DNS Bot Information",
        description="Automatische DNS-Verwaltung mit Cloudflare Integration",
        color=discord.Color.gold(),
        timestamp=datetime.now()
    )
    
    embed.add_field(name="Version", value="2.0", inline=True)
    embed.add_field(name="Developer", value="Jawollo07", inline=True)
    embed.add_field(name="Source", value="[GitHub](https://github.com/Jawollo07/DC-ddns.git)", inline=True)
    embed.add_field(name="Befehle", value="/update, /status, /renewcert, /info", inline=False)
    embed.add_field(name="Auto-Update", value=f"Alle {AUTO_UPDATE_INTERVAL_MIN} Minuten", inline=True)
    embed.add_field(name="Überwachte Records", value=f"{', '.join(RECORD_TYPES)}", inline=True)
    embed.add_field(name="Web-Control-Panel", value=f"http://{WEB_HOST}:{WEB_PORT}", inline=True)
    
    await interaction.response.send_message(embed=embed)

# Fehlerbehandlung
@bot.event
async def on_command_error(ctx, error):
    """Globale Fehlerbehandlung"""
    if isinstance(error, commands.CommandNotFound):
        return
    
    logger.error(f"Command Error: {error}")
    
    if isinstance(error, commands.CheckFailure):
        await ctx.send("🚫 Keine Berechtigung für diesen Befehl.", ephemeral=True)
    else:
        await ctx.send("❌ Ein unerwarteter Fehler ist aufgetreten.", ephemeral=True)

# 🔄 Auto-Update Loop Error Handling
@auto_update_loop.error
async def auto_update_loop_error(error):
    """Fehlerbehandlung für die Auto-Update Loop"""
    logger.error(f"Auto-Update Loop Error: {error}")
    # Versuche die Loop nach einem Fehler neu zu starten
    await asyncio.sleep(60)
    auto_update_loop.restart()

# ▶️ Bot starten
if __name__ == "__main__":
    if not all([CLOUDFLARE_API_TOKEN, ZONE_ID, DISCORD_BOT_TOKEN]):
        logger.error("Fehlende Umgebungsvariablen! Bitte .env Datei überprüfen.")
        exit(1)
    
    logger.info("Starting DNS Bot with Web Control Panel...")
    bot.run(DISCORD_BOT_TOKEN)
