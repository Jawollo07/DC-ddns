import discord
from discord.ext import commands, tasks
from discord import app_commands
import requests
import subprocess
import os
from dotenv import load_dotenv

# 🌐 .env laden
load_dotenv()

# 🐛 Debug-Modus
DEBUG = True

# 🔧 Konfiguration
CLOUDFLARE_API_TOKEN = os.getenv("CF_API_TOKEN")
ZONE_ID = os.getenv("CF_ZONE_ID")
DISCORD_BOT_TOKEN = os.getenv("DISCORD_BOT_TOKEN")
AUTO_UPDATE_INTERVAL_MIN = int(os.getenv("AUTO_UPDATE_INTERVAL", "10"))
ALLOWED_USER_IDS = [int(uid.strip()) for uid in os.getenv("ALLOWED_USER_IDS", "").split(",") if uid.strip()]

# 🌩️ Nur diese Typen werden berücksichtigt
RECORD_TYPES = ["A", "AAAA"]

# Zertifikatdaten
CERTBOT_DOMAINS = os.getenv("CERTBOT_DOMAINS", "").split(",")
CERTBOT_EMAIL = os.getenv("CERTBOT_EMAIL", "")


def debug_log(msg):
    if DEBUG:
        print(f"[DEBUG] {msg}")


# 🌐 Öffentliche IP abrufen
def get_public_ip(v6=False):
    try:
        url = "https://api64.ipify.org" if v6 else "https://api.ipify.org"
        ip = requests.get(url, timeout=5).text.strip()
        debug_log(f"Öffentliche {'IPv6' if v6 else 'IPv4'}: {ip}")
        return ip
    except Exception as e:
        print(f"[❌] IP Fehler: {e}")
        return None


# 🔍 Alle DNS-Records abrufen
def get_all_dns_records():
    url = f"https://api.cloudflare.com/client/v4/zones/{ZONE_ID}/dns_records"
    headers = {"Authorization": f"Bearer {CLOUDFLARE_API_TOKEN}"}
    records = []
    page = 1
    per_page = 100

    while True:
        resp = requests.get(f"{url}?page={page}&per_page={per_page}", headers=headers)
        debug_log(f"GET {url}?page={page} → {resp.status_code}")
        data = resp.json()
        if not data.get("success"):
            break
        records.extend(data["result"])
        if page * per_page >= data["result_info"]["total_count"]:
            break
        page += 1

    # nur A und AAAA zurückgeben
    return [r for r in records if r["type"] in RECORD_TYPES]


# 🔁 Einzelnen DNS-Record aktualisieren
def update_dns_record(record, ip):
    if not ip:
        return f"❌ Keine {record['type']}-IP angegeben für {record['name']}."

    record_id = record["id"]
    record_type = record["type"]
    proxied = record.get("proxied", False)
    url = f"https://api.cloudflare.com/client/v4/zones/{ZONE_ID}/dns_records/{record_id}"
    headers = {
        "Authorization": f"Bearer {CLOUDFLARE_API_TOKEN}",
        "Content-Type": "application/json"
    }
    payload = {
        "type": record_type,
        "name": record["name"],
        "content": ip,
        "ttl": 120,
        "proxied": proxied
    }

    debug_log(f"PUT {url}")
    debug_log(f"Nutzlast: {payload}")

    resp = requests.put(url, headers=headers, json=payload)
    debug_log(f"Antwortcode: {resp.status_code}")
    debug_log(f"Antworttext: {resp.text}")

    if resp.status_code == 200 and resp.json().get("success"):
        print(f"[✅] {record_type}-Record {record['name']} aktualisiert auf {ip} (proxied={proxied})")
        return f"✅ {record_type} {record['name']}: `{ip}` aktualisiert (proxied={proxied})."
    else:
        print(f"[❌] Fehler bei {record_type} {record['name']}: {resp.text}")
        return f"❌ Fehler bei {record_type} {record['name']}-Update."


# 🔐 User-Prüfung
def is_authorized(user_id):
    return user_id in ALLOWED_USER_IDS


# 🔑 Certbot
def renew_certbot():
    if not CERTBOT_DOMAINS or not CERTBOT_EMAIL:
        return "⚠️ Keine Zertifikatsdaten konfiguriert."

    try:
        cmd = [
            "sudo", "certbot", "certonly", "--standalone",
            "--agree-tos", "--non-interactive", "--expand",
            "--email", CERTBOT_EMAIL
        ]
        for domain in CERTBOT_DOMAINS:
            if domain.strip():
                cmd += ["-d", domain.strip()]
        debug_log(f"Certbot-Befehl: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            return "✅ Certbot-Zertifikate wurden erfolgreich erneuert."
        else:
            return f"❌ Certbot-Fehler:\n{result.stderr}"
    except Exception as e:
        return f"❌ Certbot-Ausnahme: {str(e)}"


# 🧠 Discord Bot
intents = discord.Intents.default()
bot = commands.Bot(command_prefix="!", intents=intents)
tree = bot.tree


@bot.event
async def on_ready():
    await tree.sync()
    print(f"✅ Bot bereit als {bot.user}")
    auto_update_loop.start()


# 🔁 Auto-Update Loop
@tasks.loop(minutes=AUTO_UPDATE_INTERVAL_MIN)
async def auto_update_loop():
    print(f"[🔁] Auto-Update (alle {AUTO_UPDATE_INTERVAL_MIN} Minuten)")
    records = get_all_dns_records()
    ipv4 = get_public_ip(False)
    ipv6 = get_public_ip(True)
    for record in records:
        ip = ipv6 if record["type"] == "AAAA" else ipv4
        if ip:
            update_dns_record(record, ip)


# 💬 /update
@tree.command(name="update", description="DNS-Einträge manuell aktualisieren")
@app_commands.describe(ipv4="IPv4 manuell setzen", ipv6="IPv6 manuell setzen")
async def update(interaction: discord.Interaction, ipv4: str = None, ipv6: str = None):
    if not is_authorized(interaction.user.id):
        await interaction.response.send_message("🚫 Keine Berechtigung.", ephemeral=True)
        return

    await interaction.response.defer()
    messages = []
    records = get_all_dns_records()
    for record in records:
        ip = None
        if record["type"] == "A":
            ip = ipv4 if ipv4 else get_public_ip(False)
        elif record["type"] == "AAAA":
            ip = ipv6 if ipv6 else get_public_ip(True)
        if ip:
            messages.append(update_dns_record(record, ip))
        else:
            messages.append(f"❌ Keine IP für {record['type']} {record['name']} ermittelt.")

    await interaction.followup.send("\n".join(messages))


# 💬 /status
@tree.command(name="status", description="Zeigt den DNS- und IP-Status")
async def status(interaction: discord.Interaction):
    if not is_authorized(interaction.user.id):
        await interaction.response.send_message("🚫 Keine Berechtigung.", ephemeral=True)
        return

    await interaction.response.defer()
    messages = []
    records = get_all_dns_records()
    ipv4 = get_public_ip(False)
    ipv6 = get_public_ip(True)

    for record in records:
        public_ip = ipv6 if record["type"] == "AAAA" else ipv4
        messages.append(f"🔎 {record['type']} {record['name']}: `{record['content']}`")
        messages.append(f"🌐 Öffentliche {record['type']}: `{public_ip}`" if public_ip else f"⚠️ {record['type']}: Keine IP")
        if record and public_ip:
            status = "✅ OK" if record["content"] == public_ip else "⚠️ Abweichung"
            messages.append(f"{status} – DNS ≠ öffentl. IP")
        messages.append("─" * 40)

    await interaction.followup.send("\n".join(messages))


# 💬 /renewcert
@tree.command(name="renewcert", description="Erneuert das SSL-Zertifikat mit Certbot")
async def renewcert(interaction: discord.Interaction):
    if not is_authorized(interaction.user.id):
        await interaction.response.send_message("🚫 Keine Berechtigung.", ephemeral=True)
        return

    await interaction.response.defer()
    result = renew_certbot()
    await interaction.followup.send(result)


# ▶️ Bot starten
bot.run(DISCORD_BOT_TOKEN)
