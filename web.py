from flask import Flask, render_template, request, jsonify, session
import threading
import logging
import os
from datetime import datetime
from dotenv import load_dotenv
import uuid # Oben zu den Imports hinzufügen

load_dotenv()
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "super-geheim-ändern-bitte")

WEB_USERNAME = os.getenv("WEB_USERNAME", "admin")
WEB_PASSWORD = os.getenv("WEB_PASSWORD", "password")
WEB_PORT = int(os.getenv("WEB_PORT", "5000"))
WEB_HOST = os.getenv("WEB_HOST", "0.0.0.0")


def start_web_interface(bot, cf_api, ip_manager, db):
    """Startet Flask in einem separaten Thread"""

    @app.route('/')
    def index():
        if not session.get('logged_in'):
            return render_template('login.html')
        return render_template('index.html')

    @app.route('/login', methods=['POST']) # type: ignore
    def login():
        username = request.form.get('username')
        password = request.form.get('password')
        if username == WEB_USERNAME and password == WEB_PASSWORD:
            session['logged_in'] = True
            session['user_id'] = username
        
            # Generiere eine Session-ID, falls sie noch nicht existiert
            if 'sid' not in session:
                session['sid'] = str(uuid.uuid4())
            
            ip = ip_manager.get_client_ip(request)
            # Jetzt nutzt du session['sid'] statt session.sid
            db.save_web_session(session['sid'], username, ip, request.headers.get('User-Agent', '')) 
            db.log_system_event("INFO", f"Web-Login: {username} ({ip})", "WEB", username)
            return jsonify({'success': True})
    @app.route('/logout')
    def logout():
        if session.get('logged_in'):
            db.log_system_event("INFO", "Web-Logout", "WEB", session.get('user_id'))
        session.pop('logged_in', None)
        session.pop('user_id', None)
        return jsonify({'success': True})
    @app.route('/api/status')
    def api_status():
        if not session.get('logged_in'):
            return jsonify({'error': 'Nicht autorisiert'}), 401
        try:
            # Aktualisiere Records von Cloudflare
            records = bot.cf_api.get_all_dns_records()
            ipv4 = bot.ip_manager.get_public_ip(False)
            ipv6 = bot.ip_manager.get_public_ip(True)
            client_ip = bot.ip_manager.get_client_ip(request)
            bot_stats = db.get_bot_stats()
                
            status_data = {
                'records': records,
                'ips': {
                'ipv4': ipv4,
                'ipv6': ipv6,
                'client_ip': client_ip
            },
            'bot_status': {
            'last_update': bot_stats.get('last_update'),
            'last_auto_update': bot_stats.get('last_auto_update'),
            'total_updates': bot_stats.get('total_updates', 0)
            }
            }
            return jsonify(status_data)
        except Exception as e:
            logger.error(f"Fehler in API Status: {e}")
            db.log_system_event("ERROR", f"API Status Fehler: {str(e)}", "WEB_INTERFACE")
            return jsonify({'error': str(e)}), 500
        
    @app.route('/api/update', methods=['POST']) # type: ignore
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
                auto_ipv4 = ip_manager.get_public_ip(False)
                auto_ipv6 = ip_manager.get_public_ip(True)
                ipv4 = ipv4 or auto_ipv4
                ipv6 = ipv6 or auto_ipv6
                
                records = cf_api.get_all_dns_records()
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
                        
                        if cf_api.update_dns_record(record["id"], record_data, "WEB", session.get('user_id', 'web_user')):
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
                        
                        if cf_api.update_dns_record(record["id"], record_data, "WEB", session.get('user_id', 'web_user')):
                            results.append(f"✅ {record['type']} {record['name']}: {ipv6}")
                            updated_count += 1
                        else:
                            results.append(f"❌ Fehler bei {record['type']} {record['name']}")
                
                # Update Bot-Statistiken
                if updated_count > 0:
                    db.update_bot_stats(updated_count)
                
                db.log_system_event("INFO", f"Web-Update: {updated_count} Records aktualisiert", "WEB_INTERFACE", session.get('user_id', 'web_user'))
                
                return jsonify({
                    'success': True,
                    'updated_count': updated_count,
                    'results': results,
                    'timestamp': datetime.now().isoformat()
                })
                
        except Exception as e:
            logger.error(f"Fehler in API Update: {e}")
            db.log_system_event("ERROR", f"API Update Fehler: {str(e)}", "WEB_INTERFACE", session.get('user_id', 'web_user'))
            return jsonify({'error': str(e)}), 500
        
        @app.route('/api/renew-cert', methods=['POST'])
        def api_renew_cert():
            if not session.get('logged_in'):
                return jsonify({'error': 'Nicht autorisiert'}), 401
            
            try:
                result = bot.certbot_manager.renew_certificates()
                return jsonify({'success': True, 'result': result})
            except Exception as e:
                logger.error(f"Fehler in API Renew Cert: {e}")
                db.log_system_event("ERROR", f"API Renew Cert Fehler: {str(e)}", "WEB_INTERFACE", session.get('user_id', 'web_user'))
                return jsonify({'error': str(e)}), 500
        
        @app.route('/api/history')
        def api_history():
            if not session.get('logged_in'):
                return jsonify({'error': 'Nicht autorisiert'}), 401
            
            try:
                limit = request.args.get('limit', 50, type=int)
                history = db.execute_query("""
                    SELECT h.*, r.name as record_name 
                    FROM ip_history h 
                    LEFT JOIN dns_records r ON h.record_id = r.id 
                    ORDER BY h.created_at DESC 
                    LIMIT %s
                """, (limit,))
                return jsonify(history)
            except Exception as e:
                logger.error(f"Fehler in API History: {e}")
                return jsonify({'error': str(e)}), 500
        
        @app.route('/api/logs')
        def api_logs():
            if not session.get('logged_in'):
                return jsonify({'error': 'Nicht autorisiert'}), 401
            
            try:
                limit = request.args.get('limit', 100, type=int)
                logs = db.get_recent_logs(limit)
                return jsonify(logs)
            except Exception as e:
                logger.error(f"Fehler in API Logs: {e}")
                return jsonify({'error': str(e)}), 500
    
# Flask im Thread starten
    def run_flask():
        app.run(host=WEB_HOST, port=WEB_PORT, debug=False, use_reloader=False)

    thread = threading.Thread(target=run_flask, daemon=True)
    thread.start()

    logger.info(f"Web-Panel gestartet → http://{WEB_HOST}:{WEB_PORT}")
    db.log_system_event("INFO", f"Web-Control-Panel gestartet (Port {WEB_PORT})", "WEB_INTERFACE")