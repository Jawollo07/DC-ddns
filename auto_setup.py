import os
import subprocess

# Liste der Umgebungsvariablen mit Beschreibung und Standardwerten
env_vars = [
    ("CF_API_TOKEN", "Cloudflare API Token", None),
    ("CF_ZONE_ID", "Cloudflare Zone ID", None),
    ("DISCORD_BOT_TOKEN", "Discord Bot Token", None),
    ("AUTO_UPDATE_INTERVAL", "Intervall für automatische Updates in Minuten (Standard: 10)", "10"),
    ("ALLOWED_USER_IDS", "Erlaubte Discord User IDs, kommasepariert (Standard: leer)", ""),
    ("WEB_USERNAME", "Benutzername für Webpanel Login (Standard: admin)", "admin"),
    ("WEB_PASSWORD", "Passwort für Webpanel Login (Standard: password)", "password"),
    ("WEB_PORT", "Port für Webpanel Server (Standard: 5000)", "5000"),
    ("WEB_HOST", "Host für Webpanel Server (Standard: 0.0.0.0)", "0.0.0.0"),
    
    # MySQL Datenbank Einstellungen
    ("MYSQL_HOST", "MySQL Hostname/Adresse (Standard: localhost)", "localhost"),
    ("MYSQL_PORT", "MySQL Portnummer (Standard: 3306)", "3306"),
    ("MYSQL_USER", "MySQL Benutzername (Standard: ddns_user)", "ddns_user"),
    ("MYSQL_PASSWORD", "MySQL Passwort", None),
    ("MYSQL_DATABASE", "MySQL Datenbankname (Standard: ddns_bot)", "ddns_bot"),

    # Certbot Einstellungen
    ("CERTBOT_DOMAINS", "Domains für Certbot SSL-Zertifikate kommasepariert", ""),
    ("CERTBOT_EMAIL", "Email Adresse für Certbot Benachrichtigungen", ""),

    # Flask Secret Key
    ("FLASK_SECRET_KEY", "Flask Secret Key zum Signieren von Sessions", "your-secret-key-here")
]

def get_input(prompt):
    """Sichere Eingabefunktion mit Exception-Handling"""
    try:
        return input(prompt).strip()
    except (EOFError, KeyboardInterrupt):
        return ''

def setup_environment():
    """Hauptfunktion für das Setup"""
    print("=" * 50)
    print("Willkommen zum DC-ddns Setup!")
    print("=" * 50)
    
    dotenv_lines = []
    
    for var_name, description, default in env_vars:
        # Erstelle den Prompt-Text
        if default is not None:
            prompt_text = f"{description} [{default}]: "
        else:
            prompt_text = f"{description}: "
        
        # Benutzereingabe abfragen
        user_input = get_input(prompt_text)
        
        # Verwende Standardwert falls Eingabe leer ist
        if not user_input and default is not None:
            user_input = default
        
        dotenv_lines.append(f'{var_name}="{user_input}"')
    
    # .env Datei schreiben
    dotenv_content = '\n'.join(dotenv_lines)
    dotenv_path = '.env'
    
    try:
        with open(dotenv_path, 'w', encoding='utf-8') as f:
            f.write(dotenv_content)
        print(f"\n✅ .env Datei wurde erstellt unter {dotenv_path}")
    except Exception as e:
        print(f"❌ Fehler beim Erstellen der .env Datei: {e}")
        return False
    
    return True

def install_dependencies():
    """Installiert die Python-Abhängigkeiten"""
    print("\n📦 Installiere Python-Abhängigkeiten...")
    
    try:
        # Prüfe ob requirements.txt existiert
        if not os.path.exists('requirements.txt'):
            print("❌ requirements.txt nicht gefunden!")
            return False
            
        subprocess.run(['pip', 'install', '-r', 'requirements.txt'], check=True)
        print("✅ Abhängigkeiten erfolgreich installiert!")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Fehler beim Installieren der Abhängigkeiten: {e}")
        return False
    except FileNotFoundError:
        print("❌ pip nicht gefunden! Stellen Sie sicher dass Python installiert ist.")
        return False

def main():
    """Hauptfunktion"""
    try:
        # Setup durchführen
        if not setup_environment():
            return
        
        # Abhängigkeiten installieren
        if not install_dependencies():
            print("⚠️  Installation der Abhängigkeiten fehlgeschlagen, fahre trotzdem fort...")
        
        # Erfolgsmeldung
        print("\n" + "=" * 50)
        print("✅ Setup abgeschlossen!")
        print("\nNächste Schritte:")
        print("1. Überprüfe die .env Datei auf Vollständigkeit")
        print("2. Starte den Bot mit: python ddns.py")
        print("3. Oder starte den Bot im Hintergrund mit: nohup python ddns.py &")
        print("=" * 50)
        
    except Exception as e:
        print(f"�️ Unerwarteter Fehler: {e}")

if __name__ == "__main__":
    main()
