# certbot.py
import subprocess
import logging
from typing import List

logger = logging.getLogger(__name__)

class CertbotManager:
    def __init__(self, domains: List[str], email: str, db):
        self.domains = domains
        self.email = email
        self.db = db

    def renew_certificates(self) -> str:
        if not self.domains or not self.email:
            return "⚠️ Keine Certbot-Domains oder E-Mail konfiguriert."

        try:
            cmd = [
                "sudo", "certbot", "renew",
                "--non-interactive", "--agree-tos",
                "--email", self.email
            ]
            # oder certonly --standalone, je nach deinem Setup
            # cmd = ["sudo", "certbot", "certonly", "--standalone", ...] + [f"-d {d}" for d in self.domains]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            if result.returncode == 0:
                self.db.log_system_event("INFO", "Certbot erfolgreich erneuert", "CERTBOT")
                return "✅ Zertifikate erneuert."
            else:
                msg = f"Certbot Fehler:\n{result.stderr}"
                self.db.log_system_event("ERROR", msg, "CERTBOT")
                return msg
        except Exception as e:
            msg = f"Certbot Exception: {e}"
            self.db.log_system_event("ERROR", msg, "CERTBOT")
            return msg