#!/bin/bash

###############################################################################
# Ubuntu Cloud Proxy Dashboard Installer
# Web-based management interface for proxy server
###############################################################################

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

echo ""
echo -e "${BLUE}╔════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║   Ubuntu Cloud Proxy Dashboard Installer      ║${NC}"
echo -e "${BLUE}╔════════════════════════════════════════════════╗${NC}"
echo ""

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   log_error "This script must be run as root"
   echo "Please run: sudo ./ubuntu-install-dashboard.sh"
   exit 1
fi

# Install Python and required tools
log_info "[1/6] Installing Python and dependencies..."
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y python3 curl || {
    log_error "Failed to install Python3"
    exit 1
}
log_success "Python3 installed"

# Install htpasswd (apache2-utils) - required for password management
log_info "[2/6] Installing Apache utilities (htpasswd)..."
if ! command -v htpasswd &>/dev/null; then
    apt-get install -y apache2-utils || {
        log_error "Failed to install apache2-utils"
        log_error "This is required for password management in the dashboard"
        exit 1
    }
    log_success "apache2-utils installed"
else
    log_success "htpasswd already available"
fi

log_info "[3/6] Creating dedicated user for dashboard..."
# Create non-root user for security
if ! id -u proxy-dashboard &>/dev/null; then
    useradd -r -s /bin/false -d /opt/proxy-dashboard proxy-dashboard
    log_success "Created proxy-dashboard user"
else
    log_success "User proxy-dashboard already exists"
fi

# Create dashboard directory
log_info "[4/6] Creating dashboard directory..."
mkdir -p /opt/proxy-dashboard
chown proxy-dashboard:proxy-dashboard /opt/proxy-dashboard

# Copy the dashboard app.py
log_info "[5/6] Creating dashboard application..."
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
BLACKLIST_FILE = '/opt/proxy-dashboard/blacklist.txt'

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

def validate_ip(ip):
    """Validate IP address format"""
    if not ip:
        return False
    # Simple IPv4 validation
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(part) <= 255 for part in parts)
    except ValueError:
        return False

def get_blacklist():
    """Get list of blacklisted IPs"""
    if not os.path.exists(BLACKLIST_FILE):
        return []
    try:
        with open(BLACKLIST_FILE, 'r') as f:
            return [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except:
        return []

def add_to_blacklist(ip):
    """Add IP to blacklist and apply iptables rule"""
    if not validate_ip(ip):
        return False, "Invalid IP address"
    
    blacklist = get_blacklist()
    if ip in blacklist:
        return False, "IP already blacklisted"
    
    try:
        # Add to file
        with open(BLACKLIST_FILE, 'a') as f:
            f.write(f"{ip}\n")
        
        # Add iptables rule to block this IP
        subprocess.run(['sudo', 'iptables', '-I', 'INPUT', '-s', ip, '-p', 'tcp', '--dport', '1080', '-j', 'DROP'], check=True)
        subprocess.run(['sudo', 'iptables', '-I', 'INPUT', '-s', ip, '-p', 'tcp', '--dport', '8888', '-j', 'DROP'], check=True)
        
        # Save iptables rules (Ubuntu)
        subprocess.run(['sudo', 'netfilter-persistent', 'save'], check=False)
        
        # Kill existing connections from this IP
        try:
            netstat_output = subprocess.check_output(['netstat', '-tn']).decode()
            for line in netstat_output.split('\n'):
                if ip in line and ('1080' in line or '8888' in line):
                    # Extract connection info and kill it
                    parts = line.split()
                    if len(parts) >= 5:
                        subprocess.run(['sudo', 'ss', '-K', 'dst', ip], check=False)
        except:
            pass
        
        return True, "IP blacklisted successfully"
    except Exception as e:
        return False, str(e)

def remove_from_blacklist(ip):
    """Remove IP from blacklist and remove iptables rule"""
    blacklist = get_blacklist()
    if ip not in blacklist:
        return False, "IP not in blacklist"
    
    try:
        # Remove from file
        with open(BLACKLIST_FILE, 'w') as f:
            for blocked_ip in blacklist:
                if blocked_ip != ip:
                    f.write(f"{blocked_ip}\n")
        
        # Remove iptables rules
        subprocess.run(['sudo', 'iptables', '-D', 'INPUT', '-s', ip, '-p', 'tcp', '--dport', '1080', '-j', 'DROP'], check=False)
        subprocess.run(['sudo', 'iptables', '-D', 'INPUT', '-s', ip, '-p', 'tcp', '--dport', '8888', '-j', 'DROP'], check=False)
        
        # Save iptables rules (Ubuntu)
        subprocess.run(['sudo', 'netfilter-persistent', 'save'], check=False)
        
        return True, "IP removed from blacklist"
    except Exception as e:
        return False, str(e)

def get_active_connections():
    """Get active proxy connections (excluding blacklisted IPs)"""
    connections = {
        'socks5': [],
        'http': []
    }

    blacklist = get_blacklist()

    try:
        # Get SOCKS5 connections
        netstat = subprocess.check_output(['netstat', '-tn'], stderr=subprocess.STDOUT).decode()
        for line in netstat.split('\n'):
            if ':1080' in line and 'ESTABLISHED' in line:
                parts = line.split()
                if len(parts) >= 5:
                    remote = parts[4].split(':')[0]
                    if remote not in blacklist:
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
                    if remote not in blacklist:
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
            # Return 401 for API requests, redirect for page requests
            if self.path.startswith('/api/'):
                self.send_response(401)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'error': 'Unauthorized'}).encode())
            else:
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
        
        elif self.path == '/api/blacklist':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            blacklist = get_blacklist()
            self.wfile.write(json.dumps({'ips': blacklist}).encode())
        
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
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'error': 'Unauthorized'}).encode())
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
        
        elif self.path == '/api/blacklist-add':
            ip = data.get('ip', [''])[0].strip()
            success, message = add_to_blacklist(ip)
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'success': success, 'message': message}).encode())
        
        elif self.path == '/api/blacklist-remove':
            ip = data.get('ip', [''])[0].strip()
            success, message = remove_from_blacklist(ip)
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'success': success, 'message': message}).encode())
        
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
            microsocks_check = subprocess.run(['sudo', 'systemctl', 'is-active', 'microsocks'],
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
            status['socks5'] = microsocks_check.stdout.strip()
        except Exception as e:
            status['socks5'] = 'error'
        
        try:
            squid_check = subprocess.run(['sudo', 'systemctl', 'is-active', 'squid'],
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
            status['http'] = squid_check.stdout.strip()
        except Exception as e:
            status['http'] = 'error'
        
        try:
            public_ip = subprocess.check_output(['curl', '-s', 'ifconfig.me'], timeout=5).decode().strip()
            status['public_ip'] = public_ip
        except Exception as e:
            status['public_ip'] = 'unknown'
        
        return status
    
    def run_diagnostics(self):
        diagnostics = {}
        
        # Check firewall rules
        try:
            iptables = subprocess.check_output(['sudo', 'iptables', '-L', 'INPUT', '-n']).decode()
            diagnostics['firewall_1080'] = 'open' if '1080' in iptables else 'blocked'
            diagnostics['firewall_8888'] = 'open' if '8888' in iptables else 'blocked'
        except:
            diagnostics['firewall_1080'] = 'error'
            diagnostics['firewall_8888'] = 'error'
        
        # Check listening ports
        try:
            netstat = subprocess.check_output(['sudo', 'netstat', '-tulpn'], stderr=subprocess.STDOUT).decode()
            diagnostics['listening_1080'] = 'yes' if ':1080' in netstat else 'no'
            diagnostics['listening_8888'] = 'yes' if ':8888' in netstat else 'no'
        except:
            diagnostics['listening_1080'] = 'error'
            diagnostics['listening_8888'] = 'error'
        
        # Check AppArmor (Ubuntu specific)
        try:
            apparmor = subprocess.check_output(['sudo', 'aa-status', '--enabled'], stderr=subprocess.STDOUT).decode()
            diagnostics['apparmor'] = 'enabled'
        except:
            diagnostics['apparmor'] = 'disabled'
        
        return diagnostics
    
    def add_proxy_user(self, username, password):
        try:
            # Add to squid htpasswd
            subprocess.run(['htpasswd', '-b', '/etc/squid/auth/passwords', username, password],
                         check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            # Restart services
            subprocess.run(['sudo', 'systemctl', 'restart', 'squid'], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            return {'success': True, 'message': f'User {username} added successfully'}
        except subprocess.CalledProcessError as e:
            return {'success': False, 'error': f'Command failed: {e.stderr.decode() if e.stderr else str(e)}'}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def restart_services(self):
        try:
            subprocess.run(['sudo', 'systemctl', 'restart', 'microsocks'], check=True)
            subprocess.run(['sudo', 'systemctl', 'restart', 'squid'], check=True)
            return {'success': True, 'message': 'Services restarted successfully'}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def auto_fix(self):
        fixes = []
        
        try:
            # Fix firewall rules
            subprocess.run(['sudo', 'iptables', '-I', 'INPUT', '-p', 'tcp', '--dport', '1080', '-j', 'ACCEPT'], check=False)
            subprocess.run(['sudo', 'iptables', '-I', 'INPUT', '-p', 'tcp', '--dport', '8888', '-j', 'ACCEPT'], check=False)
            fixes.append('Firewall rules added')
            
            # Restart services
            subprocess.run(['sudo', 'systemctl', 'restart', 'microsocks'], check=True)
            subprocess.run(['sudo', 'systemctl', 'restart', 'squid'], check=True)
            fixes.append('Services restarted')
            
            # Fix permissions (Ubuntu uses proxy:proxy or squid:squid)
            subprocess.run(['sudo', 'chown', '-R', 'proxy:proxy', '/var/spool/squid'], check=False)
            subprocess.run(['sudo', 'chown', '-R', 'proxy:proxy', '/var/log/squid'], check=False)
            fixes.append('Permissions fixed')
            
            return {'success': True, 'fixes': fixes}
        except Exception as e:
            return {'success': False, 'error': str(e), 'fixes': fixes}
    
    def get_setup_html(self):
        return '''<!DOCTYPE html><html><head><title>Proxy Dashboard - Setup</title><meta name="viewport" content="width=device-width, initial-scale=1"><style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}.setup-box{background:white;border-radius:10px;padding:40px;box-shadow:0 10px 40px rgba(0,0,0,0.2);max-width:400px;width:100%}h1{color:#333;margin-bottom:10px;font-size:24px}p{color:#666;margin-bottom:30px}.form-group{margin-bottom:20px}label{display:block;margin-bottom:5px;color:#333;font-weight:600}input{width:100%;padding:12px;border:2px solid #e5e7eb;border-radius:6px;font-size:14px}input:focus{outline:none;border-color:#667eea}button{width:100%;background:#667eea;color:white;border:none;padding:12px;border-radius:6px;font-size:16px;font-weight:600;cursor:pointer}button:hover{background:#5568d3}.alert{padding:12px;border-radius:6px;margin-bottom:20px}.alert-error{background:#fee2e2;color:#991b1b}</style></head><body><div class="setup-box"><h1>Proxy Dashboard</h1><p>Set a password to secure your dashboard</p><div id="message"></div><form id="setupForm"><div class="form-group"><label>Password</label><input type="password" id="password" required minlength="8"></div><div class="form-group"><label>Confirm Password</label><input type="password" id="confirm" required minlength="8"></div><button type="submit">Set Password</button></form></div><script>document.getElementById('setupForm').addEventListener('submit',function(e){e.preventDefault();const password=document.getElementById('password').value;const confirm=document.getElementById('confirm').value;const messageDiv=document.getElementById('message');if(password!==confirm){messageDiv.innerHTML='<div class="alert alert-error">Passwords do not match!</div>';return}if(password.length<8){messageDiv.innerHTML='<div class="alert alert-error">Password must be at least 8 characters!</div>';return}fetch('/api/setup',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'password='+encodeURIComponent(password)+'&confirm='+encodeURIComponent(confirm)}).then(r=>r.json()).then(data=>{if(data.success){window.location.href='/'}else{messageDiv.innerHTML='<div class="alert alert-error">'+data.error+'</div>'}})});</script></body></html>'''
    
    def get_login_html(self):
        return '''<!DOCTYPE html><html><head><title>Proxy Dashboard - Login</title><meta name="viewport" content="width=device-width, initial-scale=1"><style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}.login-box{background:white;border-radius:10px;padding:40px;box-shadow:0 10px 40px rgba(0,0,0,0.2);max-width:400px;width:100%}h1{color:#333;margin-bottom:10px;font-size:24px}p{color:#666;margin-bottom:30px}.form-group{margin-bottom:20px}label{display:block;margin-bottom:5px;color:#333;font-weight:600}input{width:100%;padding:12px;border:2px solid #e5e7eb;border-radius:6px;font-size:14px}input:focus{outline:none;border-color:#667eea}button{width:100%;background:#667eea;color:white;border:none;padding:12px;border-radius:6px;font-size:16px;font-weight:600;cursor:pointer}button:hover{background:#5568d3}.alert{padding:12px;border-radius:6px;margin-bottom:20px}.alert-error{background:#fee2e2;color:#991b1b}</style></head><body><div class="login-box"><h1>Proxy Dashboard</h1><p>Please enter your password</p><div id="message"></div><form id="loginForm"><div class="form-group"><label>Password</label><input type="password" id="password" required></div><button type="submit">Login</button></form></div><script>document.getElementById('loginForm').addEventListener('submit',function(e){e.preventDefault();const password=document.getElementById('password').value;fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'password='+encodeURIComponent(password)}).then(r=>r.json()).then(data=>{if(data.success){window.location.href='/'}else{document.getElementById('message').innerHTML='<div class="alert alert-error">Invalid password!</div>'}})});</script></body></html>'''
    
    def get_dashboard_html(self):
        return '''<!DOCTYPE html><html><head><title>Proxy Dashboard</title><meta name="viewport" content="width=device-width, initial-scale=1"><style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);min-height:100vh;padding:20px}.container{max-width:1200px;margin:0 auto}.header{background:white;border-radius:10px;padding:30px;margin-bottom:20px;box-shadow:0 10px 40px rgba(0,0,0,0.1);display:flex;justify-content:space-between;align-items:center}.header h1{color:#333;margin-bottom:10px;font-size:28px}.header p{color:#666}.logout-btn{background:#ef4444;color:white;border:none;padding:10px 20px;border-radius:6px;cursor:pointer;font-size:14px;font-weight:600;text-decoration:none}.logout-btn:hover{background:#dc2626}.grid{display:grid;grid-template-columns:repeat(2,1fr);gap:20px;margin-bottom:20px}@media(max-width:768px){.grid{grid-template-columns:1fr}}.card{background:white;border-radius:10px;padding:25px;box-shadow:0 10px 40px rgba(0,0,0,0.1)}.card.full-width{grid-column:1/-1}.card h2{color:#333;margin-bottom:15px;font-size:20px;border-bottom:2px solid #667eea;padding-bottom:10px}.status-badge{display:inline-block;padding:5px 15px;border-radius:20px;font-size:14px;font-weight:600;margin:5px 0}.status-active{background:#10b981;color:white}.status-inactive{background:#ef4444;color:white}.status-open{background:#10b981;color:white}.status-yes{background:#10b981;color:white}.status-no{background:#ef4444;color:white}.btn{background:#667eea;color:white;border:none;padding:10px 20px;border-radius:6px;cursor:pointer;font-size:14px;font-weight:600;transition:all 0.3s;margin:5px;display:inline-block}.btn:hover{background:#5568d3}.btn-success{background:#10b981}.btn-success:hover{background:#059669}.btn-danger{background:#ef4444}.btn-danger:hover{background:#dc2626}.btn-small{padding:5px 10px;font-size:12px}.form-group{margin:15px 0}.form-group label{display:block;margin-bottom:5px;color:#333;font-weight:600}.form-group input{width:100%;padding:10px;border:2px solid #e5e7eb;border-radius:6px;font-size:14px}.form-group input:focus{outline:none;border-color:#667eea}.alert{padding:15px;border-radius:6px;margin:15px 0}.alert-success{background:#d1fae5;color:#065f46}.alert-error{background:#fee2e2;color:#991b1b}.diagnostic-item{display:flex;justify-content:space-between;align-items:center;padding:12px 0;border-bottom:1px solid #e5e7eb}.diagnostic-item:last-child{border-bottom:none}.diagnostic-item span:first-child{color:#555;font-weight:500}.connection-list{list-style:none;padding:0;max-height:300px;overflow-y:auto}.connection-list li{padding:10px 14px;background:#f9fafb;margin:8px 0;border-radius:6px;font-family:monospace;font-size:13px;display:flex;justify-content:space-between;align-items:center;border-left:3px solid #667eea}.connection-list li span{color:#333}.blacklist-item{display:flex;justify-content:space-between;align-items:center;padding:12px;background:#fef2f2;margin:8px 0;border-radius:6px;font-family:monospace;border-left:3px solid #ef4444}.blacklist-item span{color:#991b1b}.section-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:15px}.ip-count{background:#667eea;color:white;padding:4px 12px;border-radius:12px;font-size:12px;font-weight:600}.empty-state{text-align:center;padding:30px;color:#9ca3af}</style></head><body><div class="container"><div class="header"><div><h1>Ubuntu Cloud Proxy Dashboard</h1><p>Monitor and manage your SOCKS5 and HTTP proxy</p></div><a href="/logout" class="logout-btn">Logout</a></div><div class="grid"><div class="card"><h2>Service Status</h2><div id="service-status">Loading...</div><div style="margin-top:15px"><button class="btn" onclick="refreshStatus()">Refresh</button><button class="btn btn-success" onclick="restartServices()">Restart Services</button></div></div><div class="card"><h2>Diagnostics</h2><div id="diagnostics">Loading...</div><div style="margin-top:15px"><button class="btn btn-danger" onclick="runAutoFix()">Auto-Fix Issues</button></div></div></div><div class="card full-width"><div class="section-header"><h2>Active Connections</h2><div id="connection-count" class="ip-count">0</div></div><div id="connections">Loading...</div></div><div class="card full-width"><h2>IP Blacklist</h2><p style="color:#666;margin-bottom:15px;font-size:14px">Block specific IP addresses from accessing your proxy</p><div class="form-group"><label>IP Address to Block</label><div style="display:flex;gap:10px"><input type="text" id="blacklist-ip" placeholder="192.168.1.100" style="flex:1"><button class="btn btn-danger" onclick="addToBlacklist()">Block IP</button></div></div><div id="blacklist-result"></div><div style="margin-top:20px"><div class="section-header"><h3 style="font-size:16px;margin:0">Blocked IPs</h3><span id="blocked-count" class="ip-count" style="background:#ef4444">0</span></div><div id="blacklist-list">Loading...</div></div></div></div><script>function refreshStatus(){fetch("/api/status").then(r=>{if(r.status===401){window.location.href='/login';return}return r.json()}).then(data=>{if(!data)return;document.getElementById("service-status").innerHTML='<div class="diagnostic-item"><span>SOCKS5 (Port 1080)</span><span class="status-badge status-'+(data.socks5==="active"?"active":"inactive")+'">'+data.socks5.toUpperCase()+'</span></div><div class="diagnostic-item"><span>HTTP Proxy (Port 8888)</span><span class="status-badge status-'+(data.http==="active"?"active":"inactive")+'">'+data.http.toUpperCase()+'</span></div><div class="diagnostic-item"><span>Public IP</span><span style="font-family:monospace;color:#667eea;font-weight:600">'+data.public_ip+"</span></div>"}).catch(e=>console.error(e));fetch("/api/connections").then(r=>{if(r.status===401){window.location.href='/login';return}return r.json()}).then(data=>{if(!data)return;const total=data.socks5.length+data.http.length;document.getElementById("connection-count").textContent=total;let html="";if(data.socks5.length>0){html+='<h3 style="color:#667eea;margin:15px 0 10px;font-size:14px;text-transform:uppercase">SOCKS5 ('+data.socks5.length+')</h3><ul class="connection-list">';Array.from(new Set(data.socks5)).forEach(ip=>html+='<li><span>'+ip+'</span><button class="btn btn-danger btn-small" onclick="blockIP(\\''+ip+'\\')">Block</button></li>');html+="</ul>"}if(data.http.length>0){html+='<h3 style="color:#667eea;margin:15px 0 10px;font-size:14px;text-transform:uppercase">HTTP ('+data.http.length+')</h3><ul class="connection-list">';Array.from(new Set(data.http)).forEach(ip=>html+='<li><span>'+ip+'</span><button class="btn btn-danger btn-small" onclick="blockIP(\\''+ip+'\\')">Block</button></li>');html+="</ul>"}if(total===0)html='<div class="empty-state"><p style="font-size:16px;font-weight:500">No Active Connections</p></div>';document.getElementById("connections").innerHTML=html}).catch(e=>console.error(e));fetch("/api/diagnostics").then(r=>{if(r.status===401){window.location.href='/login';return}return r.json()}).then(data=>{if(!data)return;document.getElementById("diagnostics").innerHTML='<div class="diagnostic-item"><span>Firewall 1080</span><span class="status-badge status-'+(data.firewall_1080==="open"?"yes":"no")+'">'+data.firewall_1080+'</span></div><div class="diagnostic-item"><span>Firewall 8888</span><span class="status-badge status-'+(data.firewall_8888==="open"?"yes":"no")+'">'+data.firewall_8888+'</span></div><div class="diagnostic-item"><span>Listening 1080</span><span class="status-badge status-'+data.listening_1080+'">'+data.listening_1080+'</span></div><div class="diagnostic-item"><span>Listening 8888</span><span class="status-badge status-'+data.listening_8888+'">'+data.listening_8888+'</span></div><div class="diagnostic-item"><span>AppArmor</span><span class="status-badge status-'+(data.apparmor==="enabled"?"yes":"no")+'">'+data.apparmor+"</span></div>"}).catch(e=>console.error(e));fetch("/api/blacklist").then(r=>{if(r.status===401){window.location.href='/login';return}return r.json()}).then(data=>{if(!data)return;document.getElementById("blocked-count").textContent=data.ips.length;let html="";if(data.ips.length>0){data.ips.forEach(ip=>html+='<div class="blacklist-item"><span>'+ip+'</span><button class="btn btn-success btn-small" onclick="unblockIP(\\''+ip+'\\')">Unblock</button></div>')}else{html='<div class="empty-state"><p>No blocked IPs</p></div>'}document.getElementById("blacklist-list").innerHTML=html}).catch(e=>console.error(e))}function restartServices(){if(!confirm("Restart services? This will interrupt connections."))return;fetch("/api/restart-services",{method:"POST"}).then(r=>{if(r.status===401){window.location.href='/login';return}return r.json()}).then(data=>{if(!data)return;alert(data.success?"Services restarted!":"Error: "+data.error);setTimeout(refreshStatus,2000)})}function runAutoFix(){if(!confirm("Run auto-fix?"))return;fetch("/api/auto-fix",{method:"POST"}).then(r=>{if(r.status===401){window.location.href='/login';return}return r.json()}).then(data=>{if(!data)return;alert(data.success?"Fixed:\\n"+data.fixes.join("\\n"):"Error: "+data.error);setTimeout(refreshStatus,2000)})}function addToBlacklist(){const ip=document.getElementById("blacklist-ip").value.trim();if(!ip||!ip.match(/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/)){alert("Enter valid IP");return}fetch("/api/blacklist-add",{method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded"},body:"ip="+encodeURIComponent(ip)}).then(r=>{if(r.status===401){window.location.href='/login';return}return r.json()}).then(data=>{if(!data)return;const div=document.getElementById("blacklist-result");div.innerHTML='<div class="alert alert-'+(data.success?"success":"error")+'">'+data.message+"</div>";if(data.success){document.getElementById("blacklist-ip").value="";setTimeout(()=>{div.innerHTML="";refreshStatus()},2000)}else{setTimeout(()=>div.innerHTML="",4000)}})}function blockIP(ip){if(!confirm("Block "+ip+"?"))return;fetch("/api/blacklist-add",{method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded"},body:"ip="+encodeURIComponent(ip)}).then(r=>{if(r.status===401){window.location.href='/login';return}return r.json()}).then(data=>{if(!data)return;alert(data.success?"Blocked "+ip:"Error: "+data.message);setTimeout(refreshStatus,1000)})}function unblockIP(ip){if(!confirm("Unblock "+ip+"?"))return;fetch("/api/blacklist-remove",{method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded"},body:"ip="+encodeURIComponent(ip)}).then(r=>{if(r.status===401){window.location.href='/login';return}return r.json()}).then(data=>{if(!data)return;alert(data.success?"Unblocked "+ip:"Error: "+data.message);setTimeout(refreshStatus,1000)})}refreshStatus();setInterval(refreshStatus,30000)</script></body></html>'''

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
log_info "[6/6] Creating systemd service..."
cat > /etc/systemd/system/proxy-dashboard.service <<EOF
[Unit]
Description=Ubuntu Cloud Proxy Dashboard
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

[Install]
WantedBy=multi-user.target
EOF

# Create sudo rules for dashboard
log_info "Creating sudo rules for dashboard functionality..."
cat > /etc/sudoers.d/proxy-dashboard <<EOF
# Allow proxy-dashboard user to manage proxy services and firewall
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
proxy-dashboard ALL=(ALL) NOPASSWD: /usr/sbin/aa-status *
proxy-dashboard ALL=(ALL) NOPASSWD: /usr/sbin/netfilter-persistent save
proxy-dashboard ALL=(ALL) NOPASSWD: /usr/bin/chown -R proxy /var/spool/squid
proxy-dashboard ALL=(ALL) NOPASSWD: /usr/bin/chown -R proxy /var/log/squid
EOF

chmod 440 /etc/sudoers.d/proxy-dashboard
log_success "Sudo rules configured"

# Enable and start service
systemctl daemon-reload
systemctl enable proxy-dashboard
systemctl start proxy-dashboard

# Verify service started
sleep 2
if ! systemctl is-active --quiet proxy-dashboard; then
    log_error "Dashboard service failed to start"
    log_info "Checking logs..."
    journalctl -u proxy-dashboard -n 20 --no-pager
    exit 1
fi

log_success "Dashboard service started"

# Configure firewall
log_info "Configuring firewall for dashboard (port 1234)..."
iptables -I INPUT -p tcp --dport 1234 -j ACCEPT

# Save rules (Ubuntu)
if command -v netfilter-persistent &>/dev/null; then
    netfilter-persistent save
    log_success "Firewall rules saved"
else
    log_warning "Installing iptables-persistent..."
    echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
    echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
    apt-get install -y iptables-persistent
    netfilter-persistent save
    log_success "Firewall rules saved"
fi

# Configure UFW if active
if systemctl is-active --quiet ufw; then
    log_info "Configuring UFW..."
    ufw allow 1234/tcp comment 'Proxy Dashboard'
    log_success "UFW configured"
fi

# Get public IP
log_info "Detecting public IP..."
PUBLIC_IP=$(curl -s -m 5 ifconfig.me || echo "UNKNOWN")

echo ""
echo -e "${GREEN}═══════════════════════════════════════════════${NC}"
echo -e "${GREEN}Dashboard installed successfully!${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════${NC}"
echo ""

if [ "$PUBLIC_IP" != "UNKNOWN" ]; then
    echo -e "Access dashboard at: ${BLUE}http://$PUBLIC_IP:1234${NC}"
else
    echo -e "Access dashboard at: ${BLUE}http://YOUR_SERVER_IP:1234${NC}"
fi

echo ""
log_warning "═══════════════════════════════════════════════"
log_warning "IMPORTANT: Configure Cloud Security Groups!"
log_warning "═══════════════════════════════════════════════"
echo ""
echo "Add Inbound Rule in your cloud provider console:"
echo ""
echo "  ┌─────────────────────────────────────┐"
echo "  │ Source:         0.0.0.0/0           │"
echo "  │ Protocol:       TCP                 │"
echo "  │ Port:           1234                │"
echo "  │ Description:    Proxy Dashboard     │"
echo "  └─────────────────────────────────────┘"
echo ""
echo -e "${YELLOW}Without this rule, dashboard will NOT be accessible!${NC}"
echo ""
echo "On first visit, you'll be prompted to set a password."
echo ""
log_info "Service status:"
systemctl status proxy-dashboard --no-pager -l -n 5 2>/dev/null || log_warning "Could not get service status"
echo ""

log_info "═══════════════════════════════════════════════"
log_info "SECURITY NOTES"
log_info "═══════════════════════════════════════════════"
echo ""
echo "  ✓ Dashboard runs as non-root user (proxy-dashboard)"
echo "  ✓ Input validation enabled (SQL/command injection protection)"
echo "  ✓ Passwords hashed with PBKDF2-SHA256 (100,000 iterations)"
echo "  ✓ Session cookies with HttpOnly flag"
echo "  ⚠ No HTTPS - use SSH tunnel or VPN for production"
echo ""
echo -e "${YELLOW}Recommended: Access via SSH tunnel:${NC}"
echo "  ssh -L 1234:localhost:1234 user@$PUBLIC_IP"
echo "  Then access: http://localhost:1234"
echo ""
log_success "Installation complete!"
echo ""
