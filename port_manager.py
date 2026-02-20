# port_manager.py
import miniupnpc
import logging
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

class PortManager:
    def __init__(self, db):
        self.db = db
        self.upnp = miniupnpc.UPnP()
        self.upnp.discoverdelay = 200

    def open_ports(self, tcp_ports: List[int] = None, udp_ports: List[int] = None) -> Dict: # type: ignore
        tcp_ports = tcp_ports or []
        udp_ports = udp_ports or []
        results = {"success": [], "error": []}

        try:
            self.upnp.discover()
            self.upnp.selectigd()
            lan_ip = self.upnp.lanaddr

            for port in tcp_ports:
                try:
                    self.upnp.addportmapping(port, 'TCP', lan_ip, port, f"DNS-Bot TCP {port}", '')
                    results["success"].append(f"TCP {port}")
                    self.db.log_system_event("INFO", f"UPnP TCP {port} geöffnet", "PORT")
                except Exception as e:
                    results["error"].append(f"TCP {port}: {e}")

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
            return {"error": [str(e)]}

    def get_active_mappings(self) -> List:
        try:
            self.upnp.discover()
            self.upnp.selectigd()
            mappings = []
            i = 0
            while True:
                m = self.upnp.getgenericportmapping(i)
                if m is None:
                    break
                mappings.append(m)
                i += 1
            return mappings
        except:
            return []