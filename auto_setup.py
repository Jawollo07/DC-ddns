import os
import subprocess

# Liste der Umgebungsvariablen mit Beschreibung und Standardwerten
env_vars = [
    ("CF_API_TOKEN", "Cloudflare API Token (CF_API_TOKEN)", None),
    ("CF_ZONE_ID", "Cloudflare Zone ID (CF_ZONE_ID)", None),
    ("DISCORD_BOT_TOKEN", "Discord Bot Token (DISCORD_BOT_TOKEN)", None),
    ("AUTO_UPDATE_INTERVAL", "Intervall für automatische Updates in Minuten (AUTO_UPDATE_INTERVAL, Standard 10)", "10"),
    ("ALLOWED_USER_IDS", "Erlaubte Discord User IDs, kommasepariert (ALLOWED_USER_IDS, Standard leer)", ""),
    ("WEB_USERNAME", "Benutzername für Webpanel Login (WEB_USERNAME, Standard admin)", "admin"),
    ("WEB_PASSWORD", "Passwort für Webpanel Login (WEB_PASSWORD, Standard password)", "password"),
    ("WEB_PORT", "Port für Webpanel Server (WEB_PORT, Standard 5000)", "5000"),
    ("WEB_HOST", "Host für Webpanel Server (WEB_HOST, Standard 0.0.0.0)", "0.0.0.0"),
    
    # MySQL Datenbank Einstellungen
    ("MYSQL_HOST", "MySQL Hostname/Adresse (MYSQL_HOST, Standard localhost)", "localhost"),
    ("MYSQL_PORT", "MySQL Portnummer (MYSQL_PORT, Standard 3306)", "3306"),
    ("MYSQL_USER", "MySQL Benutzername  (MYSQL_USER, Standard ddns_user)", "ddns_user"),
    ("MYSQL_PASSWORD", "MySQL Passwort  (MYSQL_PASSWORD, Standard ddns_password)", None),
    ("MYSQL_DATABASE", "MySQL Datenbankname  (MYSQL_DATABASE, Standard ddns_bot)", "ddns_bot"),

    # Certbot Einstellungen
    (	CERTBOT_DOMAINS := 'CERTBOT_DOMAINS', 'Domains für Certbot SSL-Zertifikate kommasepariert', '' ), 
    (	CERTBOT_EMAIL := 'CERTBOT_EMAIL', 'Email Adresse für Certbot Benachrichtigungen', '' ), 

	# Flask Secret Key
	('FLASK_SECRET_KEY', 'Flask Secret Key zum Signieren von Sessions', 'your-secret-key-here') 
]

print("Willkommen zum DC-ddns Setup! Bitte gib die folgenden Werte ein:")
dotenv_lines = []
for var_name, description, default in env_vars:
	if default:
		prompt_text = f'{description} [{default}]: '
	else:
		prompt_text = f'{description}: '
def get_input(prompt):
	try:
		return input(prompt).strip()	except EOFError:	return '' # falls kein Input möglich ist
for var_name, description, default in env_vars:	user_input = get_input(prompt_text) or default or '' 	dotenv_lines.append(f'{var_name}="{user_input}"') 
dotenv_content = '\\n'.join(dotenv_lines) 
dotenv_path = '.env' with open(dotenv_path,'w') as f: f.write(dotenv_content) print(f'.env Datei wurde erstellt unter {dotenv_path}') print('Installiere Python-Abhängigkeiten...') subprocess.run(['pip','install','-r','requirements.txt'], check=True) print('Setup abgeschlossen! Starte den Bot mit: python ddns.py')
