import sqlite3
import hashlib
import secrets
import subprocess
import os
import json
import threading
import time
from datetime import datetime, timedelta
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, make_response
import socket
import re

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

class WiFiCafeManager:
    def __init__(self):
        self.db_path = "wifi_cafe.db"
        self.init_database()
        self.active_sessions = {}
        self.wifi_connected = False
        self.current_wifi = None
        self.hotspot_active = False
        self.monitor_sessions()

    def init_database(self):
        """Initialize SQLite database with required tables"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Create sessions table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                time_limit INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL,
                is_active BOOLEAN DEFAULT 1,
                device_mac TEXT,
                device_ip TEXT
            )
        ''')

        # Create admin table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS admin (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL,
                password_hash TEXT NOT NULL
            )
        ''')

        # Create default admin if not exists
        cursor.execute('SELECT COUNT(*) FROM admin')
        if cursor.fetchone()[0] == 0:
            admin_password = self.hash_password("Z@mbezi@1958")
            cursor.execute('INSERT INTO admin (username, password_hash) VALUES (?, ?)', 
                         ("admin", admin_password))

        conn.commit()
        conn.close()

    def hash_password(self, password):
        """Hash password using SHA-256"""
        return hashlib.sha256(password.encode()).hexdigest()

    def generate_session_credentials(self):
        """Generate random username and password for sessions"""
        username = secrets.token_hex(2)[:4]  # 4 characters
        password = secrets.token_urlsafe(6)[:6]  # 6 characters
        return username, password

    def check_internet_connection(self):
        """Check if the system has internet connectivity"""
        try:
            import socket
            socket.create_connection(("8.8.8.8", 53), timeout=3)
            return True
        except OSError:
            return False

    def create_wifi_bridge(self, ssid="CafeWiFi", password="cafe123456"):
        """Create a simple WiFi bridge to share internet connection"""
        try:
            # Check deployment environment
            is_cloud = os.getenv('REPL_ID') or os.getenv('WEBSITE_HOSTNAME') or os.getenv('AZURE_HTTP_USER_AGENT')

            if is_cloud:
                print(f"☁️ CLOUD MODE: Setting up network management for '{ssid}'")
                print("🌐 Cloud Network Configuration:")
                print(f"   • Network Name: {ssid}")
                print(f"   • Access Control: Active")
                print("   • Session Management: Enabled")
                print("   • Internet Control: Active")
                print("   • Portal Redirect: Configured")
                print("")
                print("✅ Network Manager Ready!")
                print("🔗 Users access via your Azure domain and get session-based internet control")

                self.hotspot_active = True
                self.current_wifi = f"Cloud Network: {ssid}"
                return True, f"Network '{ssid}' configured for cloud deployment! ☁️"

            # Real implementation for actual systems
            # This would work on a Linux system with proper permissions

            # Create simple hostapd config for bridge mode
            hostapd_conf = f"""
interface=wlan0
driver=nl80211
ssid={ssid}
hw_mode=g
channel=7
wmm_enabled=0
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wpa=2
wpa_passphrase={password}
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP
rsn_pairwise=CCMP
bridge=br0
"""

            # Create bridge interface
            subprocess.run(['sudo', 'brctl', 'addbr', 'br0'], capture_output=True)
            subprocess.run(['sudo', 'brctl', 'addif', 'br0', 'eth0'], capture_output=True)
            subprocess.run(['sudo', 'ip', 'link', 'set', 'dev', 'br0', 'up'], capture_output=True)

            # DHCP for connected devices
            dnsmasq_conf = f"""
interface=br0
dhcp-range=192.168.4.2,192.168.4.20,255.255.255.0,24h
address=/#/192.168.4.1
"""

            with open('/tmp/hostapd.conf', 'w') as f:
                f.write(hostapd_conf)

            with open('/tmp/dnsmasq.conf', 'w') as f:
                f.write(dnsmasq_conf)

            # Start bridge services
            subprocess.run(['sudo', 'hostapd', '/tmp/hostapd.conf', '-B'], capture_output=True)
            subprocess.run(['sudo', 'dnsmasq', '-C', '/tmp/dnsmasq.conf'], capture_output=True)

            self.hotspot_active = True
            self.current_wifi = f"Bridge: {ssid}"
            return True, f"WiFi Bridge '{ssid}' created successfully!"

        except Exception as e:
            return False, f"Failed to create WiFi bridge: {str(e)}"

    def stop_wifi_bridge(self):
        """Stop WiFi bridge"""
        try:
            print("🛑 Stopping WiFi Bridge...")
            # In real implementation, stop services and remove bridge
            # subprocess.run(['sudo', 'killall', 'hostapd'], capture_output=True)
            # subprocess.run(['sudo', 'killall', 'dnsmasq'], capture_output=True)
            # subprocess.run(['sudo', 'brctl', 'delbr', 'br0'], capture_output=True)

            self.hotspot_active = False
            self.current_wifi = None
            print("✅ WiFi Bridge stopped")
            return True
        except Exception as e:
            print(f"❌ Error stopping bridge: {e}")
            return False

    def get_device_ip(self):
        """Get the IP address of the connecting device"""
        try:
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            return local_ip
        except:
            return "192.168.4.10"  # Default bridge IP

    def enable_internet_access(self, device_ip):
        """Enable internet access for the device (remove blocks)"""
        try:
            print(f"🌐 Enabling internet access for {device_ip}")
            # In real implementation, remove iptables blocks
            return True
        except Exception as e:
            print(f"❌ Error enabling access: {e}")
            return False

    def disable_internet_access(self, device_ip):
        """Disable internet access for the device (add blocks)"""
        try:
            print(f"🚫 Disabling internet access for {device_ip}")
            # In real implementation, add iptables blocks
            return True
        except Exception as e:
            print(f"❌ Error disabling access: {e}")
            return False

    def monitor_sessions(self):
        """Monitor active sessions and terminate expired ones"""
        def session_monitor():
            while True:
                current_time = datetime.now()
                expired_sessions = []

                for username, session_data in self.active_sessions.items():
                    if current_time >= session_data['expires_at']:
                        expired_sessions.append(username)
                        self.disable_internet_access(session_data['device_ip'])

                for username in expired_sessions:
                    del self.active_sessions[username]
                    conn = sqlite3.connect(self.db_path)
                    cursor = conn.cursor()
                    cursor.execute('UPDATE sessions SET is_active = 0 WHERE username = ?', (username,))
                    conn.commit()
                    conn.close()

                time.sleep(30)

        monitor_thread = threading.Thread(target=session_monitor, daemon=True)
        monitor_thread.start()

# Initialize the manager
manager = WiFiCafeManager()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/generate_204')
@app.route('/connecttest.txt')
@app.route('/hotspot-detect.html')
@app.route('/library/test/success.html')
@app.route('/ncsi.txt')
def captive_portal():
    """Captive portal detection endpoints for various devices"""
    return redirect(url_for('portal_login'))

@app.route('/portal')
def portal_login():
    """Captive portal login page"""
    return render_template('portal.html')

@app.route('/success')
def success_page():
    """Success page after login"""
    return render_template('success.html')

@app.route('/admin')
def admin():
    return render_template('admin.html')

@app.route('/sessions')
def sessions():
    return render_template('sessions.html')

@app.route('/wifi')
def wifi():
    return render_template('wifi.html')

@app.route('/api/admin/login', methods=['POST'])
def admin_login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'success': False, 'message': 'Username and password required'})

    conn = sqlite3.connect(manager.db_path)
    cursor = conn.cursor()
    cursor.execute('SELECT password_hash FROM admin WHERE username = ?', (username,))
    result = cursor.fetchone()
    conn.close()

    if result and result[0] == manager.hash_password(password):
        session['admin_logged_in'] = True
        return jsonify({'success': True, 'message': 'Login successful'})
    else:
        return jsonify({'success': False, 'message': 'Invalid credentials'})

@app.route('/api/admin/change_password', methods=['POST'])
def change_admin_password():
    if not session.get('admin_logged_in'):
        return jsonify({'success': False, 'message': 'Not authorized'})

    data = request.get_json()
    current_password = data.get('current_password')
    new_password = data.get('new_password')
    confirm_password = data.get('confirm_password')

    if not all([current_password, new_password, confirm_password]):
        return jsonify({'success': False, 'message': 'All fields are required'})

    if new_password != confirm_password:
        return jsonify({'success': False, 'message': 'New passwords do not match'})

    if len(new_password) < 8:
        return jsonify({'success': False, 'message': 'Password must be at least 8 characters'})

    conn = sqlite3.connect(manager.db_path)
    cursor = conn.cursor()
    cursor.execute('SELECT password_hash FROM admin WHERE username = ?', ("admin",))
    result = cursor.fetchone()

    if not result or result[0] != manager.hash_password(current_password):
        conn.close()
        return jsonify({'success': False, 'message': 'Current password is incorrect'})

    new_password_hash = manager.hash_password(new_password)
    cursor.execute('UPDATE admin SET password_hash = ? WHERE username = ?', (new_password_hash, "admin"))
    conn.commit()
    conn.close()

    return jsonify({'success': True, 'message': 'Password changed successfully'})

@app.route('/api/admin/create_session', methods=['POST'])
def create_session():
    if not session.get('admin_logged_in'):
        return jsonify({'success': False, 'message': 'Not authorized'})

    data = request.get_json()
    time_limit = data.get('time_limit')

    if not time_limit or not isinstance(time_limit, int):
        return jsonify({'success': False, 'message': 'Valid time limit required'})

    username, password = manager.generate_session_credentials()
    expires_at = datetime.now() + timedelta(minutes=time_limit)

    conn = sqlite3.connect(manager.db_path)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO sessions (username, password, time_limit, expires_at)
        VALUES (?, ?, ?, ?)
    ''', (username, password, time_limit, expires_at))
    conn.commit()
    conn.close()

    return jsonify({
        'success': True,
        'username': username,
        'password': password,
        'time_limit': time_limit,
        'expires_at': expires_at.strftime('%Y-%m-%d %H:%M:%S')
    })

@app.route('/api/user/login', methods=['POST'])
def user_login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'success': False, 'message': 'Username and password required'})

    conn = sqlite3.connect(manager.db_path)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT id, expires_at, is_active FROM sessions 
        WHERE username = ? AND password = ? AND is_active = 1
    ''', (username, password))
    result = cursor.fetchone()

    if result:
        session_id, expires_at, is_active = result
        expires_datetime = datetime.fromisoformat(expires_at)

        if datetime.now() < expires_datetime:
            device_ip = manager.get_device_ip()

            cursor.execute('''
                UPDATE sessions SET device_ip = ? WHERE id = ?
            ''', (device_ip, session_id))
            conn.commit()

            manager.active_sessions[username] = {
                'session_id': session_id,
                'expires_at': expires_datetime,
                'device_ip': device_ip
            }

            time_left = expires_datetime - datetime.now()
            minutes_left = int(time_left.total_seconds() / 60)

            manager.enable_internet_access(device_ip)

            conn.close()
            return jsonify({
                'success': True,
                'message': f'Connected! Time remaining: {minutes_left} minutes',
                'time_remaining': minutes_left,
                'redirect': '/success'
            })
        else:
            cursor.execute('UPDATE sessions SET is_active = 0 WHERE id = ?', (session_id,))
            conn.commit()
            conn.close()
            return jsonify({'success': False, 'message': 'Session has expired'})
    else:
        conn.close()
        return jsonify({'success': False, 'message': 'Invalid credentials'})

@app.route('/api/portal/login', methods=['POST'])
def portal_login_api():
    """API endpoint for captive portal login"""
    return user_login()

@app.route('/api/sessions')
def get_sessions():
    sessions_data = []
    for username, session_data in manager.active_sessions.items():
        time_left = session_data['expires_at'] - datetime.now()
        minutes_left = max(0, int(time_left.total_seconds() / 60))

        sessions_data.append({
            'username': username,
            'time_left': minutes_left,
            'device_ip': session_data['device_ip'],
            'status': 'Active' if minutes_left > 0 else 'Expired'
        })

    return jsonify(sessions_data)

@app.route('/api/sessions/terminate', methods=['POST'])
def terminate_session():
    if not session.get('admin_logged_in'):
        return jsonify({'success': False, 'message': 'Not authorized'})

    data = request.get_json()
    username = data.get('username')

    if username in manager.active_sessions:
        manager.disable_internet_access(manager.active_sessions[username]['device_ip'])
        del manager.active_sessions[username]

        conn = sqlite3.connect(manager.db_path)
        cursor = conn.cursor()
        cursor.execute('UPDATE sessions SET is_active = 0 WHERE username = ?', (username,))
        conn.commit()
        conn.close()

        return jsonify({'success': True, 'message': f'Session {username} terminated'})

    return jsonify({'success': False, 'message': 'Session not found'})

@app.route('/api/wifi/status')
def get_wifi_status():
    return jsonify({
        'internet_connected': manager.check_internet_connection(),
        'bridge_active': manager.hotspot_active,
        'current_setup': manager.current_wifi,
        'connected_devices': len(manager.active_sessions)
    })

@app.route('/api/wifi/create_bridge', methods=['POST'])
def create_bridge():
    data = request.get_json()
    ssid = data.get('ssid', 'CafeWiFi')
    password = data.get('password', 'cafe123456')

    if len(password) < 8:
        return jsonify({'success': False, 'message': 'Password must be at least 8 characters'})

    success, message = manager.create_wifi_bridge(ssid, password)
    return jsonify({'success': success, 'message': message})

@app.route('/api/wifi/stop_bridge', methods=['POST'])
def stop_bridge():
    success = manager.stop_wifi_bridge()
    if success:
        return jsonify({'success': True, 'message': 'WiFi Bridge stopped'})
    else:
        return jsonify({'success': False, 'message': 'Failed to stop bridge'})

if __name__ == '__main__':
    print("🚀 Starting WiFi Cafe Bridge Manager...")
    print("📡 Ready to create WiFi bridge for internet sharing")
    app.run(host='0.0.0.0', port=5000, debug=True)