# cloudflare.py
import requests
import logging
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)

class CloudflareAPI:
    def __init__(self, api_token: str, zone_id: str, db):
        self.api_token = api_token
        self.zone_id = zone_id
        self.db = db
        self.base_url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records"
        self.headers = {
            "Authorization": f"Bearer {api_token}",
            "Content-Type": "application/json"
        }

    def get_all_dns_records(self) -> List[Dict[str, Any]]:
        records = []
        page = 1
        per_page = 100

        while True:
            try:
                url = f"{self.base_url}?page={page}&per_page={per_page}"
                r = requests.get(url, headers=self.headers, timeout=10)
                r.raise_for_status()
                data = r.json()
                if not data.get("success"):
                    logger.error(f"Cloudflare Fehler: {data.get('errors')}")
                    break
                records.extend(data["result"])
                for rec in data["result"]:
                    if rec["type"] in ["A", "AAAA"]:
                        self.db.save_dns_record(rec)
                if page * per_page >= data["result_info"]["total_count"]:
                    break
                page += 1
            except Exception as e:
                logger.error(f"Cloudflare get_all Fehler: {e}")
                break
        return [r for r in records if r["type"] in ["A", "AAAA"]]

    def update_dns_record(self, record_id: str, data: Dict, change_type: str = "MANUAL", changed_by: str = "SYSTEM") -> bool:
        if not record_id or record_id == "AUTO_UPDATE":
            logger.error(f"Ungültige Record-ID: {record_id}")
            return False

        try:
            old = self.db.get_dns_record_by_id(record_id)
            old_ip = old["content"] if old else None

            url = f"{self.base_url}/{record_id}"
            r = requests.put(url, headers=self.headers, json=data, timeout=10)
            r.raise_for_status()
            resp = r.json()
            if resp.get("success"):
                data["id"] = record_id
                self.db.save_dns_record(data)
                if old_ip and old_ip != data["content"]:
                    self.db.log_ip_change(record_id, old_ip, data["content"], change_type, changed_by)
                return True
            else:
                logger.error(f"Cloudflare Update Fehler: {resp.get('errors')}")
                return False
        except Exception as e:
            logger.error(f"Update Fehler: {e}")
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