# database.py
from copy import Error

import mariadb # Statt mysql.connector
import logging
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)

class MySQLManager:
    def __init__(self):
        from dotenv import load_dotenv
        import os
        load_dotenv()

        self.host = os.getenv("MYSQL_HOST", "localhost")
        self.port = int(os.getenv("MYSQL_PORT", "3306"))
        self.user = os.getenv("MYSQL_USER", "ddns_user")
        self.password = os.getenv("MYSQL_PASSWORD", "ddns_password")
        self.database = os.getenv("MYSQL_DATABASE", "ddns_bot")
        
        self.connection = None
        self.connect()
        self.init_database()

    def connect(self):
        try:
            self.connection = mariadb.connect(
                host=self.host, port=self.port, user=self.user,
                password=self.password, database=self.database
            )
            logger.info("MariaDB Verbindung hergestellt")
        except mariadb.Error as e:
            logger.error(f"MariaDB Verbindungsfehler: {e}")
            raise

    def init_database(self):
        try:
            cursor = self.connection.cursor() # type: ignore
            # dns_records
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS dns_records (
                    id VARCHAR(255) PRIMARY KEY,
                    name VARCHAR(255) NOT NULL,
                    type VARCHAR(10) NOT NULL,
                    content TEXT NOT NULL,
                    ttl INT DEFAULT 120,
                    proxied BOOLEAN DEFAULT FALSE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
                )
            """)
            # ip_history, bot_stats, system_logs, web_sessions → wie in deinem Originalcode
            # (kopiere die restlichen CREATE TABLE Anweisungen hierher)

            cursor.execute("INSERT IGNORE INTO bot_stats (id, total_updates) VALUES (1, 0)")
            self.connection.commit() # type: ignore
            cursor.close()
            logger.info("Datenbank-Tabellen initialisiert")
        except Error as e:
            logger.error(f"DB-Initialisierungsfehler: {e}")
            raise

    def execute_query(self, query: str, params: tuple = None) -> Any: # type: ignore
        cursor = self.connection.cursor(dictionary=True) # type: ignore
        try:
            cursor.execute(query, params or ())
            if query.strip().upper().startswith(('INSERT', 'UPDATE', 'DELETE')):
                self.connection.commit() # type: ignore
                return cursor.lastrowid
            else:
                return cursor.fetchall()
        except Error as e:
            logger.error(f"DB Query Fehler: {e}\nQuery: {query}")
            self.connection.rollback() # type: ignore
            raise
        finally:
            cursor.close()
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
    
    def log_system_event(self, level: str, message: str, source: str = "SYSTEM", user_id: str = None): # type: ignore
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
