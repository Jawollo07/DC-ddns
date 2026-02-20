import requests
import logging
from typing import Optional

logger = logging.getLogger(__name__)

class IPManager:
    # Liste von zuverlässigen Diensten
    SERVICES_V4 = [
        "https://api.ipify.org",
        "https://4.icanhazip.com",
        "https://v4.ident.me",
        "https://ipv4.seeip.org"
    ]
    
    SERVICES_V6 = [
        "https://api64.ipify.org",
        "https://6.icanhazip.com",
        "https://v6.ident.me",
        "https://ipv6.seeip.org"
    ]

    @staticmethod
    def get_public_ip(v6: bool = False) -> Optional[str]:
        services = IPManager.SERVICES_V6 if v6 else IPManager.SERVICES_V4
        
        for url in services:
            try:
                # Kurzer Timeout, damit der Bot nicht hängt, wenn ein Dienst langsam ist
                r = requests.get(url, timeout=5)
                r.raise_for_status()
                ip = r.text.strip()
                
                # Einfache Validierung, ob es wie eine IP aussieht
                if v6 and ":" in ip:
                    logger.info(f"IP gefunden ({url}): {ip}")
                    return ip
                elif not v6 and "." in ip:
                    logger.info(f"IP gefunden ({url}): {ip}")
                    return ip
                    
            except Exception as e:
                logger.warning(f"Dienst {url} fehlgeschlagen: {e}")
                continue # Nächsten Dienst versuchen
        
        logger.error("Alle IP-Dienste sind fehlgeschlagen!")
        return None

    @staticmethod
    def get_client_ip(request) -> str:
        # Bestehende Logik für Reverse Proxys (Nginx/Cloudflare)
        if request.headers.get("X-Forwarded-For"):
            return request.headers["X-Forwarded-For"].split(",")[0].strip()
        return request.headers.get("X-Real-IP", request.remote_addr)