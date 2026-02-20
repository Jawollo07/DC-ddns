# bot.py
import discord
from discord.ext import commands, tasks
from discord import app_commands
import logging
from datetime import datetime
from dotenv import load_dotenv
import os
import asyncio

# Eigene Module
from database import MySQLManager
from cloudflare import CloudflareAPI
from ip_utils import IPManager
from certbot import CertbotManager
from port_manager import PortManager
from web import start_web_interface, app  # Flask wird hier importiert, aber in web.py definiert

load_dotenv()

# ─── Konfiguration ──────────────────────────────────────────────────────────────
CLOUDFLARE_API_TOKEN = os.getenv("CF_API_TOKEN")
ZONE_ID = os.getenv("CF_ZONE_ID")
DISCORD_BOT_TOKEN = os.getenv("DISCORD_BOT_TOKEN")
AUTO_UPDATE_INTERVAL_MIN = int(os.getenv("AUTO_UPDATE_INTERVAL", "10"))
ALLOWED_USER_IDS = [int(uid.strip()) for uid in os.getenv("ALLOWED_USER_IDS", "").split(",") if uid.strip()]

RECORD_TYPES = ["A", "AAAA"]
CERTBOT_DOMAINS = [d.strip() for d in os.getenv("CERTBOT_DOMAINS", "").split(",") if d.strip()]
CERTBOT_EMAIL = os.getenv("CERTBOT_EMAIL", "")

WEB_PORT = int(os.getenv("WEB_PORT", "5000"))
WEB_HOST = os.getenv("WEB_HOST", "0.0.0.0")

# Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.FileHandler("dns_bot.log"), logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

# ─── Bot Klasse ────────────────────────────────────────────────────────────────
class DNSBot(commands.Bot):
    def __init__(self):
        intents = discord.Intents.default()
        super().__init__(command_prefix="!", intents=intents)

        self.db = MySQLManager()
        self.cf_api = CloudflareAPI(CLOUDFLARE_API_TOKEN, ZONE_ID, self.db) # type: ignore
        self.ip_manager = IPManager()
        self.certbot_manager = CertbotManager(CERTBOT_DOMAINS, CERTBOT_EMAIL, self.db)
        self.port_manager = PortManager(self.db)

        self.last_update = None
        self.update_count = 0

    async def setup_hook(self):
        await self.tree.sync()
        logger.info("Slash-Commands synchronisiert")
        self.db.log_system_event("INFO", "Discord Bot gestartet und Commands sync", "DISCORD_BOT")

    def is_authorized(self, user_id: int) -> bool:
        return user_id in ALLOWED_USER_IDS


bot = DNSBot()


# ─── Auto-Update Loop ──────────────────────────────────────────────────────────
@tasks.loop(minutes=AUTO_UPDATE_INTERVAL_MIN)
async def auto_update_loop(): # type: ignore
    logger.info(f"Auto-Update gestartet (alle {AUTO_UPDATE_INTERVAL_MIN} min)")
    try:
        records = bot.cf_api.get_all_dns_records()
        ipv4 = bot.ip_manager.get_public_ip(False)
        ipv6 = bot.ip_manager.get_public_ip(True)

        if not records:
            logger.warning("Keine DNS-Records gefunden")
            return

        update_count = 0
        messages = []

        for record in records:
            if record["type"] not in RECORD_TYPES:
                continue
            target_ip = ipv6 if record["type"] == "AAAA" else ipv4
            if not target_ip or record["content"] == target_ip:
                continue

            record_data = {
                "type": record["type"],
                "name": record["name"],
                "content": target_ip,
                "ttl": 120,
                "proxied": record.get("proxied", False)
            }

            if bot.cf_api.update_dns_record(
                record["id"], record_data, change_type="AUTO", changed_by="AUTO_UPDATE"
            ):
                update_count += 1
                messages.append(f"{record['type']} {record['name']} → {target_ip}")

        if update_count > 0:
            bot.db.update_bot_stats(update_count, is_auto_update=True)
            logger.info(f"Auto-Update: {update_count} Records aktualisiert")
            bot.db.log_system_event(
                "INFO",
                f"Auto-Update: {update_count} Records geändert\n" + "\n".join(messages[:5]),
                "AUTO_UPDATE"
            )

        bot.last_update = datetime.now() # type: ignore
        bot.update_count += update_count

    except Exception as e:
        logger.error(f"Auto-Update Fehler: {e}")
        bot.db.log_system_event("ERROR", f"Auto-Update Fehler: {e}", "AUTO_UPDATE")


@auto_update_loop.error # type: ignore
async def auto_update_error(error):
    logger.error(f"Auto-Update Loop Error: {error}")
    await asyncio.sleep(60)
    auto_update_loop.restart()


# ─── Session Cleanup ───────────────────────────────────────────────────────────
@tasks.loop(hours=24)
async def session_cleanup_loop(): # type: ignore
    try:
        bot.db.cleanup_old_sessions(24)
        logger.info("Alte Web-Sessions bereinigt")
    except Exception as e:
        logger.error(f"Session Cleanup Fehler: {e}")


# ─── Events ────────────────────────────────────────────────────────────────────
@bot.event
async def on_ready():
    logger.info(f"Bot online als {bot.user}")
    needed_ports = [WEB_PORT, 80, 443]
    res = bot.port_manager.open_ports(tcp_ports=needed_ports)
    logger.info(f"UPnP Port-Status: {res}")

    # Web-Interface starten
    start_web_interface(bot, bot.cf_api, bot.ip_manager, bot.db)

    auto_update_loop.start()
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
        
        bot.last_update = datetime.now() # type: ignore
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
async def update(interaction: discord.Interaction, ipv4: str = None, ipv6: str = None): # type: ignore
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
        
        bot.last_update = datetime.now() # type: ignore
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
@auto_update_loop.error # type: ignore
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
    bot.run(DISCORD_BOT_TOKEN) # type: ignore