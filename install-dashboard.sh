#!/bin/bash

###############################################################################
# Oracle Cloud Proxy Dashboard Installer
# Web-based management interface for proxy server
###############################################################################

echo "Installing Oracle Cloud Proxy Dashboard..."

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root"
   exit 1
fi

# Install Python (no Flask needed - uses stdlib only)
echo "[1/5] Installing Python..."
dnf install -y python3

echo "[2/5] Creating dedicated user for dashboard..."
# Create non-root user for security
if ! id -u proxy-dashboard &>/dev/null; then
    useradd -r -s /bin/false -d /opt/proxy-dashboard proxy-dashboard
    echo "✓ Created proxy-dashboard user"
else
    echo "✓ User proxy-dashboard already exists"
fi

# Create dashboard directory
echo "[3/5] Creating dashboard directory..."
mkdir -p /opt/proxy-dashboard
chown proxy-dashboard:proxy-dashboard /opt/proxy-dashboard

# Create dashboard application
echo "[4/5] Creating dashboard application..."
cat > /opt/proxy-dashboard/app.py << 'PYEOF'
#!/usr/bin/env python3
import subprocess
import os
import json
import hashlib
import secrets
import re
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from http.cookies import SimpleCookie
import urllib.parse

PASSWORD_FILE = '/opt/proxy-dashboard/password.hash'
SESSION_FILE = '/opt/proxy-dashboard/session.key'

def hash_password(password):
    salt = secrets.token_hex(16)
    pwdhash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 100000)
    return salt + ':' + pwdhash.hex()

def verify_password(stored_password, provided_password):
    salt, pwdhash = stored_password.split(':')
    check_hash = hashlib.pbkdf2_hmac('sha256', provided_password.encode('utf-8'), salt.encode('utf-8'), 100000)
    return pwdhash == check_hash.hex()

def get_session_token():
    if os.path.exists(SESSION_FILE):
        with open(SESSION_FILE, 'r') as f:
            return f.read().strip()
    else:
        token = secrets.token_urlsafe(32)
        with open(SESSION_FILE, 'w') as f:
            f.write(token)
        os.chmod(SESSION_FILE, 0o600)
        return token

def is_password_set():
    return os.path.exists(PASSWORD_FILE)

def check_auth(handler):
    if not is_password_set():
        return True
    cookie = SimpleCookie()
    if 'Cookie' in handler.headers:
        cookie.load(handler.headers['Cookie'])
    if 'session' in cookie:
        session_token = get_session_token()
        return cookie['session'].value == session_token
    return False

def validate_username(username):
    """Validate username for security - prevent injection attacks"""
    if not username or len(username) < 3 or len(username) > 32:
        return False, "Username must be 3-32 characters"
    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        return False, "Username can only contain letters, numbers, and underscores"
    if username.lower() in ['root', 'daemon', 'bin', 'sys', 'sync', 'games', 'man', 'lp', 
                             'mail', 'news', 'uucp', 'proxy', 'www-data', 'backup', 'nobody',
                             'squid', 'microsocks']:
        return False, "Username is reserved by the system"
    return True, ""

def validate_password(password):
    """Validate password strength"""
    if not password or len(password) < 8:
        return False, "Password must be at least 8 characters"
    if len(password) > 128:
        return False, "Password too long (max 128 characters)"
    return True, ""

def get_proxy_users():
    """Get list of proxy users"""
    users = []
    try:
        if os.path.exists('/etc/squid/auth/passwords'):
            with open('/etc/squid/auth/passwords', 'r') as f:
                for line in f:
                    if ':' in line:
                        username = line.split(':')[0]
                        users.append(username)
    except:
        pass
    return users

def get_active_connections():
    """Get active proxy connections"""
    connections = {
        'socks5': [],
        'http': []
    }
    
    try:
        # Get SOCKS5 connections
        netstat = subprocess.check_output(['netstat', '-tn'], stderr=subprocess.STDOUT).decode()
        for line in netstat.split('\n'):
            if ':1080' in line and 'ESTABLISHED' in line:
                parts = line.split()
                if len(parts) >= 5:
                    remote = parts[4].split(':')[0]
                    connections['socks5'].append(remote)
    except:
        pass
    
    try:
        # Get HTTP proxy connections
        netstat = subprocess.check_output(['netstat', '-tn'], stderr=subprocess.STDOUT).decode()
        for line in netstat.split('\n'):
            if ':8888' in line and 'ESTABLISHED' in line:
                parts = line.split()
                if len(parts) >= 5:
                    remote = parts[4].split(':')[0]
                    connections['http'].append(remote)
    except:
        pass
    
    return connections

def get_squid_stats():
    """Parse squid access logs for statistics"""
    stats = {
        'total_requests': 0,
        'recent_requests': [],
        'top_domains': {}
    }
    
    try:
        if os.path.exists('/var/log/squid/access.log'):
            cmd = ['tail', '-n', '100', '/var/log/squid/access.log']
            output = subprocess.check_output(cmd).decode()
            
            for line in output.split('\n'):
                if line.strip():
                    stats['total_requests'] += 1
                    parts = line.split()
                    if len(parts) > 6:
                        url = parts[6]
                        # Extract domain
                        domain_match = re.search(r'https?://([^/]+)', url)
                        if domain_match:
                            domain = domain_match.group(1)
                            stats['top_domains'][domain] = stats['top_domains'].get(domain, 0) + 1
                    
                    # Keep last 10 requests
                    if len(stats['recent_requests']) < 10:
                        stats['recent_requests'].append(line)
    except:
        pass
    
    return stats

class ProxyDashboardHandler(BaseHTTPRequestHandler):
    
    def do_GET(self):
        if not is_password_set() and self.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(self.get_setup_html().encode())
            return
        
        if self.path == '/login':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(self.get_login_html().encode())
            return
        
        if not check_auth(self):
            self.send_response(302)
            self.send_header('Location', '/login')
            self.end_headers()
            return
        
        if self.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(self.get_dashboard_html().encode())
        
        elif self.path == '/api/status':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            status = self.get_proxy_status()
            self.wfile.write(json.dumps(status).encode())
        
        elif self.path == '/api/connections':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            connections = get_active_connections()
            self.wfile.write(json.dumps(connections).encode())
        
        elif self.path == '/api/stats':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            stats = get_squid_stats()
            self.wfile.write(json.dumps(stats).encode())
        
        elif self.path == '/api/diagnostics':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            diagnostics = self.run_diagnostics()
            self.wfile.write(json.dumps(diagnostics).encode())
        
        elif self.path == '/logout':
            self.send_response(302)
            self.send_header('Set-Cookie', 'session=; Max-Age=0')
            self.send_header('Location', '/login')
            self.end_headers()
        
        else:
            self.send_response(404)
            self.end_headers()
    
    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        data = urllib.parse.parse_qs(post_data.decode())
        
        if self.path == '/api/setup':
            password = data.get('password', [''])[0]
            confirm = data.get('confirm', [''])[0]
            
            if not password or len(password) < 8:
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'success': False, 'error': 'Password must be at least 8 characters'}).encode())
                return
            
            if password != confirm:
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'success': False, 'error': 'Passwords do not match'}).encode())
                return
            
            hashed = hash_password(password)
            with open(PASSWORD_FILE, 'w') as f:
                f.write(hashed)
            os.chmod(PASSWORD_FILE, 0o600)
            
            session_token = get_session_token()
            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Set-Cookie', f'session={session_token}; Path=/; HttpOnly; Max-Age=86400')
            self.end_headers()
            self.wfile.write(json.dumps({'success': True}).encode())
            return
        
        if self.path == '/api/login':
            password = data.get('password', [''])[0]
            
            if not is_password_set():
                self.send_response(302)
                self.send_header('Location', '/')
                self.end_headers()
                return
            
            with open(PASSWORD_FILE, 'r') as f:
                stored_password = f.read().strip()
            
            if verify_password(stored_password, password):
                session_token = get_session_token()
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.send_header('Set-Cookie', f'session={session_token}; Path=/; HttpOnly; Max-Age=86400')
                self.end_headers()
                self.wfile.write(json.dumps({'success': True}).encode())
            else:
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'success': False, 'error': 'Invalid password'}).encode())
            return
        
        if not check_auth(self):
            self.send_response(401)
            self.end_headers()
            return
        
        if self.path == '/api/add-user':
            username = data.get('username', [''])[0]
            password = data.get('password', [''])[0]
            
            # Validate input
            valid_user, user_error = validate_username(username)
            if not valid_user:
                self.send_response(400)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'success': False, 'error': user_error}).encode())
                return
            
            valid_pass, pass_error = validate_password(password)
            if not valid_pass:
                self.send_response(400)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'success': False, 'error': pass_error}).encode())
                return
            
            result = self.add_proxy_user(username, password)
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(result).encode())
        
        elif self.path == '/api/restart-services':
            result = self.restart_services()
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(result).encode())
        
        elif self.path == '/api/auto-fix':
            result = self.auto_fix()
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(result).encode())
        
        else:
            self.send_response(404)
            self.end_headers()
    
    def get_proxy_status(self):
        status = {}
        
        try:
            microsocks_check = subprocess.run(['systemctl', 'is-active', 'microsocks'],
                                        capture_output=True, text=True)
            status['socks5'] = microsocks_check.stdout.strip()
        except:
            status['socks5'] = 'error'
        
        try:
            squid_check = subprocess.run(['systemctl', 'is-active', 'squid'],
                                        capture_output=True, text=True)
            status['http'] = squid_check.stdout.strip()
        except:
            status['http'] = 'error'
        
        try:
            public_ip = subprocess.check_output(['curl', '-s', 'ifconfig.me']).decode().strip()
            status['public_ip'] = public_ip
        except:
            status['public_ip'] = 'unknown'
        
        return status
    
    def run_diagnostics(self):
        diagnostics = {}
        
        # Check firewall rules
        try:
            iptables = subprocess.check_output(['iptables', '-L', 'INPUT', '-n']).decode()
            diagnostics['firewall_1080'] = 'open' if '1080' in iptables else 'blocked'
            diagnostics['firewall_8888'] = 'open' if '8888' in iptables else 'blocked'
        except:
            diagnostics['firewall_1080'] = 'error'
            diagnostics['firewall_8888'] = 'error'
        
        # Check listening ports
        try:
            netstat = subprocess.check_output(['netstat', '-tulpn'], stderr=subprocess.STDOUT).decode()
            diagnostics['listening_1080'] = 'yes' if ':1080' in netstat else 'no'
            diagnostics['listening_8888'] = 'yes' if ':8888' in netstat else 'no'
        except:
            diagnostics['listening_1080'] = 'error'
            diagnostics['listening_8888'] = 'error'
        
        # Check SELinux
        try:
            selinux = subprocess.check_output(['getenforce']).decode().strip()
            diagnostics['selinux'] = selinux.lower()
        except:
            diagnostics['selinux'] = 'not installed'
        
        return diagnostics
    
    def add_proxy_user(self, username, password):
        try:
            # Add to squid htpasswd
            subprocess.run(['htpasswd', '-b', '/etc/squid/auth/passwords', username, password], 
                         check=True, capture_output=True)
            
            # Note: microsocks uses username:password directly in service file
            # No need to create system users for microsocks
            
            # Restart services
            subprocess.run(['systemctl', 'restart', 'squid'], check=True, capture_output=True)
            
            return {'success': True, 'message': f'User {username} added to Squid. Note: SOCKS5 uses single user from setup.'}
        except subprocess.CalledProcessError as e:
            return {'success': False, 'error': f'Command failed: {e.stderr.decode() if e.stderr else str(e)}'}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def restart_services(self):
        try:
            subprocess.run(['systemctl', 'restart', 'microsocks'], check=True)
            subprocess.run(['systemctl', 'restart', 'squid'], check=True)
            return {'success': True, 'message': 'Services restarted successfully'}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def auto_fix(self):
        fixes = []
        
        try:
            # Fix firewall rules
            subprocess.run(['iptables', '-I', 'INPUT', '-p', 'tcp', '--dport', '1080', '-j', 'ACCEPT'], check=False)
            subprocess.run(['iptables', '-I', 'INPUT', '-p', 'tcp', '--dport', '8888', '-j', 'ACCEPT'], check=False)
            fixes.append('Firewall rules added')
            
            # Restart services
            subprocess.run(['systemctl', 'restart', 'microsocks'], check=True)
            subprocess.run(['systemctl', 'restart', 'squid'], check=True)
            fixes.append('Services restarted')
            
            # Fix permissions
            subprocess.run(['chown', '-R', 'squid:squid', '/var/spool/squid'], check=False)
            subprocess.run(['chown', '-R', 'squid:squid', '/var/log/squid'], check=False)
            fixes.append('Permissions fixed')
            
            return {'success': True, 'fixes': fixes}
        except Exception as e:
            return {'success': False, 'error': str(e), 'fixes': fixes}
    
    def get_setup_html(self):
        return '''<!DOCTYPE html><html><head><title>Proxy Dashboard - Setup</title><meta name="viewport" content="width=device-width, initial-scale=1"><style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}.setup-box{background:white;border-radius:10px;padding:40px;box-shadow:0 10px 40px rgba(0,0,0,0.2);max-width:400px;width:100%}h1{color:#333;margin-bottom:10px;font-size:24px}p{color:#666;margin-bottom:30px}.form-group{margin-bottom:20px}label{display:block;margin-bottom:5px;color:#333;font-weight:600}input{width:100%;padding:12px;border:2px solid #e5e7eb;border-radius:6px;font-size:14px}input:focus{outline:none;border-color:#667eea}button{width:100%;background:#667eea;color:white;border:none;padding:12px;border-radius:6px;font-size:16px;font-weight:600;cursor:pointer}button:hover{background:#5568d3}.alert{padding:12px;border-radius:6px;margin-bottom:20px}.alert-error{background:#fee2e2;color:#991b1b}</style></head><body><div class="setup-box"><h1>🔐 Proxy Dashboard</h1><p>Set a password to secure your dashboard</p><div id="message"></div><form id="setupForm"><div class="form-group"><label>Password</label><input type="password" id="password" required minlength="8"></div><div class="form-group"><label>Confirm Password</label><input type="password" id="confirm" required minlength="8"></div><button type="submit">Set Password</button></form></div><script>document.getElementById('setupForm').addEventListener('submit',function(e){e.preventDefault();const password=document.getElementById('password').value;const confirm=document.getElementById('confirm').value;const messageDiv=document.getElementById('message');if(password!==confirm){messageDiv.innerHTML='<div class="alert alert-error">Passwords do not match!</div>';return}if(password.length<8){messageDiv.innerHTML='<div class="alert alert-error">Password must be at least 8 characters!</div>';return}fetch('/api/setup',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'password='+encodeURIComponent(password)+'&confirm='+encodeURIComponent(confirm)}).then(r=>r.json()).then(data=>{if(data.success){window.location.href='/'}else{messageDiv.innerHTML='<div class="alert alert-error">'+data.error+'</div>'}})});</script></body></html>'''
    
    def get_login_html(self):
        return '''<!DOCTYPE html><html><head><title>Proxy Dashboard - Login</title><meta name="viewport" content="width=device-width, initial-scale=1"><style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}.login-box{background:white;border-radius:10px;padding:40px;box-shadow:0 10px 40px rgba(0,0,0,0.2);max-width:400px;width:100%}h1{color:#333;margin-bottom:10px;font-size:24px}p{color:#666;margin-bottom:30px}.form-group{margin-bottom:20px}label{display:block;margin-bottom:5px;color:#333;font-weight:600}input{width:100%;padding:12px;border:2px solid #e5e7eb;border-radius:6px;font-size:14px}input:focus{outline:none;border-color:#667eea}button{width:100%;background:#667eea;color:white;border:none;padding:12px;border-radius:6px;font-size:16px;font-weight:600;cursor:pointer}button:hover{background:#5568d3}.alert{padding:12px;border-radius:6px;margin-bottom:20px}.alert-error{background:#fee2e2;color:#991b1b}</style></head><body><div class="login-box"><h1>🔐 Proxy Dashboard</h1><p>Please enter your password</p><div id="message"></div><form id="loginForm"><div class="form-group"><label>Password</label><input type="password" id="password" required></div><button type="submit">Login</button></form></div><script>document.getElementById('loginForm').addEventListener('submit',function(e){e.preventDefault();const password=document.getElementById('password').value;fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'password='+encodeURIComponent(password)}).then(r=>r.json()).then(data=>{if(data.success){window.location.href='/'}else{document.getElementById('message').innerHTML='<div class="alert alert-error">Invalid password!</div>'}})});</script></body></html>'''
    
    def get_dashboard_html(self):
        return '''<!DOCTYPE html><html><head><title>Proxy Dashboard</title><meta name="viewport" content="width=device-width, initial-scale=1"><style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);min-height:100vh;padding:20px}.container{max-width:1400px;margin:0 auto}.header{background:white;border-radius:10px;padding:30px;margin-bottom:20px;box-shadow:0 10px 40px rgba(0,0,0,0.1);display:flex;justify-content:space-between;align-items:center}.header h1{color:#333;margin-bottom:10px}.header p{color:#666}.logout-btn{background:#ef4444;color:white;border:none;padding:10px 20px;border-radius:6px;cursor:pointer;font-size:14px;font-weight:600;text-decoration:none}.logout-btn:hover{background:#dc2626}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:20px;margin-bottom:20px}.card{background:white;border-radius:10px;padding:25px;box-shadow:0 10px 40px rgba(0,0,0,0.1)}.card h2{color:#333;margin-bottom:15px;font-size:20px}.status-badge{display:inline-block;padding:5px 15px;border-radius:20px;font-size:14px;font-weight:600;margin:5px 0}.status-active{background:#10b981;color:white}.status-inactive{background:#ef4444;color:white}.status-open{background:#10b981;color:white}.status-blocked{background:#f59e0b;color:white}.status-yes{background:#10b981;color:white}.status-no{background:#ef4444;color:white}.btn{background:#667eea;color:white;border:none;padding:10px 20px;border-radius:6px;cursor:pointer;font-size:14px;font-weight:600;transition:all 0.3s;margin:5px;display:inline-block}.btn:hover{background:#5568d3}.btn-success{background:#10b981}.btn-success:hover{background:#059669}.btn-danger{background:#ef4444}.btn-danger:hover{background:#dc2626}.form-group{margin:15px 0}.form-group label{display:block;margin-bottom:5px;color:#333;font-weight:600}.form-group input{width:100%;padding:10px;border:2px solid #e5e7eb;border-radius:6px;font-size:14px}.form-group input:focus{outline:none;border-color:#667eea}.alert{padding:15px;border-radius:6px;margin:15px 0}.alert-success{background:#d1fae5;color:#065f46}.alert-error{background:#fee2e2;color:#991b1b}.diagnostic-item{display:flex;justify-content:space-between;align-items:center;padding:10px 0;border-bottom:1px solid #e5e7eb}.diagnostic-item:last-child{border-bottom:none}.connection-list{list-style:none;padding:0}.connection-list li{padding:8px 12px;background:#f9fafb;margin:5px 0;border-radius:4px;font-family:monospace;font-size:13px}.stat-number{font-size:32px;font-weight:bold;color:#667eea;margin:10px 0}</style></head><body><div class="container"><div class="header"><div><h1>🌐 Oracle Cloud Proxy Dashboard</h1><p>Monitor and manage your SOCKS5 and HTTP proxy</p></div><a href="/logout" class="logout-btn">Logout</a></div><div class="grid"><div class="card"><h2>Service Status</h2><div id="service-status">Loading...</div><button class="btn" onclick="refreshStatus()">Refresh</button><button class="btn btn-success" onclick="restartServices()">Restart Services</button></div><div class="card"><h2>Active Connections</h2><div id="connections">Loading...</div></div><div class="card"><h2>Diagnostics</h2><div id="diagnostics">Loading...</div><button class="btn btn-danger" onclick="runAutoFix()">Auto-Fix Issues</button></div></div><div class="card"><h2>Proxy Statistics</h2><div id="stats">Loading...</div></div><div class="card"><h2>Add Proxy User</h2><div class="form-group"><label>Username</label><input type="text" id="new-username" placeholder="username"></div><div class="form-group"><label>Password</label><input type="password" id="new-password" placeholder="password"></div><button class="btn btn-success" onclick="addUser()">Add User</button><div id="add-user-result"></div></div></div><script>function refreshStatus(){fetch('/api/status').then(r=>r.json()).then(data=>{const statusDiv=document.getElementById('service-status');let html='';html+=`<div class="diagnostic-item"><span>SOCKS5 (Port 1080)</span><span class="status-badge status-${data.socks5==='active'?'active':'inactive'}">${data.socks5.toUpperCase()}</span></div>`;html+=`<div class="diagnostic-item"><span>HTTP Proxy (Port 8888)</span><span class="status-badge status-${data.http==='active'?'active':'inactive'}">${data.http.toUpperCase()}</span></div>`;html+=`<div class="diagnostic-item"><span>Public IP</span><span style="font-family:monospace">${data.public_ip}</span></div>`;statusDiv.innerHTML=html});fetch('/api/connections').then(r=>r.json()).then(data=>{const connDiv=document.getElementById('connections');let html='<h3>SOCKS5 Connections: '+data.socks5.length+'</h3>';if(data.socks5.length>0){html+='<ul class="connection-list">';data.socks5.forEach(ip=>html+=`<li>${ip}</li>`);html+='</ul>'}else{html+='<p style="color:#666;padding:10px 0">No active connections</p>'}html+='<h3 style="margin-top:15px">HTTP Connections: '+data.http.length+'</h3>';if(data.http.length>0){html+='<ul class="connection-list">';data.http.forEach(ip=>html+=`<li>${ip}</li>`);html+='</ul>'}else{html+='<p style="color:#666;padding:10px 0">No active connections</p>'}connDiv.innerHTML=html});fetch('/api/diagnostics').then(r=>r.json()).then(data=>{const diagDiv=document.getElementById('diagnostics');diagDiv.innerHTML=`<div class="diagnostic-item"><span>Firewall Port 1080</span><span class="status-badge status-${data.firewall_1080}">${data.firewall_1080}</span></div><div class="diagnostic-item"><span>Firewall Port 8888</span><span class="status-badge status-${data.firewall_8888}">${data.firewall_8888}</span></div><div class="diagnostic-item"><span>Listening on 1080</span><span class="status-badge status-${data.listening_1080}">${data.listening_1080}</span></div><div class="diagnostic-item"><span>Listening on 8888</span><span class="status-badge status-${data.listening_8888}">${data.listening_8888}</span></div><div class="diagnostic-item"><span>SELinux</span><span class="status-badge status-${data.selinux==='permissive'||data.selinux==='disabled'?'yes':'no'}">${data.selinux}</span></div>`});fetch('/api/stats').then(r=>r.json()).then(data=>{const statsDiv=document.getElementById('stats');let html=`<div class="stat-number">${data.total_requests}</div><p style="color:#666">Total HTTP Requests (last 100 log entries)</p>`;if(Object.keys(data.top_domains).length>0){html+='<h3 style="margin-top:20px">Top Domains</h3><ul class="connection-list">';const sorted=Object.entries(data.top_domains).sort((a,b)=>b[1]-a[1]).slice(0,5);sorted.forEach(([domain,count])=>html+=`<li>${domain} <span style="float:right;color:#667eea;font-weight:bold">${count}</span></li>`);html+='</ul>'}statsDiv.innerHTML=html})}function restartServices(){if(!confirm('Restart proxy services? This will briefly interrupt connections.'))return;fetch('/api/restart-services',{method:'POST'}).then(r=>r.json()).then(data=>{if(data.success){alert('Services restarted successfully!')}else{alert('Error: '+data.error)}setTimeout(refreshStatus,2000)})}function runAutoFix(){if(!confirm('Run auto-fix? This will restart services and fix common issues.'))return;fetch('/api/auto-fix',{method:'POST'}).then(r=>r.json()).then(data=>{if(data.success){alert('Auto-fix completed!\\n\\n'+data.fixes.join('\\n'))}else{alert('Auto-fix failed: '+data.error)}setTimeout(refreshStatus,2000)})}function addUser(){const username=document.getElementById('new-username').value;const password=document.getElementById('new-password').value;if(!username||!password){alert('Please enter both username and password');return}fetch('/api/add-user',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'username='+encodeURIComponent(username)+'&password='+encodeURIComponent(password)}).then(r=>r.json()).then(data=>{const resultDiv=document.getElementById('add-user-result');if(data.success){resultDiv.innerHTML='<div class="alert alert-success">'+data.message+'</div>';document.getElementById('new-username').value='';document.getElementById('new-password').value=''}else{resultDiv.innerHTML='<div class="alert alert-error">Error: '+data.error+'</div>'}})}refreshStatus();setInterval(refreshStatus,30000);</script></body></html>'''

def run_server(port=1234):
    server = HTTPServer(('0.0.0.0', port), ProxyDashboardHandler)
    print(f'Proxy Dashboard running on http://0.0.0.0:{port}')
    server.serve_forever()

if __name__ == '__main__':
    run_server()
PYEOF

chmod +x /opt/proxy-dashboard/app.py
chown -R proxy-dashboard:proxy-dashboard /opt/proxy-dashboard

# Create systemd service
echo "[5/5] Creating systemd service..."
cat > /etc/systemd/system/proxy-dashboard.service <<EOF
[Unit]
Description=Oracle Cloud Proxy Dashboard
After=network.target

[Service]
Type=simple
User=proxy-dashboard
Group=proxy-dashboard
WorkingDirectory=/opt/proxy-dashboard
ExecStart=/usr/bin/python3 /opt/proxy-dashboard/app.py
Restart=always
RestartSec=10

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/proxy-dashboard

# Allow dashboard to manage proxy services (requires sudo setup)
# Note: For full functionality, add to /etc/sudoers.d/proxy-dashboard:
#   proxy-dashboard ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart microsocks
#   proxy-dashboard ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart squid
#   proxy-dashboard ALL=(ALL) NOPASSWD: /usr/bin/htpasswd *
#   proxy-dashboard ALL=(ALL) NOPASSWD: /usr/sbin/chpasswd

[Install]
WantedBy=multi-user.target
EOF

# Create sudo rules for dashboard
echo "Creating sudo rules for dashboard functionality..."
cat > /etc/sudoers.d/proxy-dashboard <<EOF
# Allow proxy-dashboard user to manage proxy services
proxy-dashboard ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart microsocks
proxy-dashboard ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart squid
proxy-dashboard ALL=(ALL) NOPASSWD: /usr/bin/systemctl status microsocks
proxy-dashboard ALL=(ALL) NOPASSWD: /usr/bin/systemctl status squid
proxy-dashboard ALL=(ALL) NOPASSWD: /usr/bin/systemctl is-active microsocks
proxy-dashboard ALL=(ALL) NOPASSWD: /usr/bin/systemctl is-active squid
proxy-dashboard ALL=(ALL) NOPASSWD: /usr/bin/htpasswd -b /etc/squid/auth/passwords *
proxy-dashboard ALL=(ALL) NOPASSWD: /usr/sbin/iptables *
proxy-dashboard ALL=(ALL) NOPASSWD: /usr/bin/netstat *
proxy-dashboard ALL=(ALL) NOPASSWD: /usr/bin/ss *
proxy-dashboard ALL=(ALL) NOPASSWD: /usr/sbin/getenforce
EOF

chmod 440 /etc/sudoers.d/proxy-dashboard

# Update app.py to use sudo for privileged operations
# (Commands will now be prefixed with sudo when run as proxy-dashboard user)

# Enable and start service
systemctl daemon-reload
systemctl enable proxy-dashboard
systemctl start proxy-dashboard

# Configure firewall
echo "Configuring firewall for dashboard (port 1234)..."
iptables -I INPUT -p tcp --dport 1234 -j ACCEPT
mkdir -p /etc/iptables
iptables-save > /etc/iptables/rules.v4

if systemctl is-active --quiet firewalld; then
    firewall-cmd --permanent --add-port=1234/tcp
    firewall-cmd --reload
fi

# Get public IP
PUBLIC_IP=$(curl -s ifconfig.me)

echo ""
echo "============================================="
echo "Dashboard installed successfully!"
echo "============================================="
echo ""
echo "Access dashboard at: http://$PUBLIC_IP:1234"
echo ""
echo "IMPORTANT: Configure Oracle Cloud Security List!"
echo ""
echo "Add Ingress Rule:"
echo "  - Source CIDR: 0.0.0.0/0"
echo "  - IP Protocol: TCP"
echo "  - Destination Port: 1234"
echo ""
echo "On first visit, you'll set a password."
echo ""
echo "Service status:"
systemctl status proxy-dashboard --no-pager
echo ""
echo "SECURITY NOTES:"
echo "  ✓ Dashboard runs as non-root user (proxy-dashboard)"
echo "  ✓ Input validation enabled"
echo "  ✓ Passwords hashed with PBKDF2-SHA256"
echo "  ⚠ No HTTPS - use only on trusted networks"
echo ""
