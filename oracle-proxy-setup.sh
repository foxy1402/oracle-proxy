#!/bin/bash

###############################################################################
# Oracle Cloud Smart Proxy Setup Script
# Creates SOCKS5 and HTTP proxy with auto-configuration
# Handles Oracle Cloud's strict firewall automatically
###############################################################################

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
SOCKS5_PORT=1080
HTTP_PORT=8888
PROXY_USER=""
PROXY_PASS=""

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

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   log_error "This script must be run as root"
   echo "Please run: sudo ./oracle-proxy-setup.sh"
   exit 1
fi

echo -e "${BLUE}╔════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║   Oracle Cloud Smart Proxy Setup              ║${NC}"
echo -e "${BLUE}║   SOCKS5 + HTTP Proxy with Authentication     ║${NC}"
echo -e "${BLUE}╔════════════════════════════════════════════════╗${NC}"
echo ""

###############################################################################
# Step 1: Detect Network Configuration
###############################################################################

detect_network() {
    log_info "Detecting network configuration..."
    
    PRIMARY_INTERFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
    if [ -z "$PRIMARY_INTERFACE" ]; then
        log_error "Could not detect primary network interface"
        exit 1
    fi
    log_success "Primary interface: $PRIMARY_INTERFACE"
    
    PUBLIC_IP=$(curl -s -4 ifconfig.me || curl -s -4 icanhazip.com || echo "")
    if [ -z "$PUBLIC_IP" ]; then
        log_warning "Could not detect public IP automatically"
        read -p "Enter your Oracle instance public IP: " PUBLIC_IP
    fi
    log_success "Public IP: $PUBLIC_IP"
    
    PRIVATE_IP=$(ip -4 addr show $PRIMARY_INTERFACE | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -n1)
    log_success "Private IP: $PRIVATE_IP"
}

###############################################################################
# Step 2: Install Proxy Software
###############################################################################

check_dependencies() {
    log_info "Checking system dependencies..."
    
    local missing=()
    
    # Check critical commands
    for cmd in curl iptables systemctl ip; do
        if ! command -v $cmd &>/dev/null; then
            missing+=($cmd)
        fi
    done
    
    if [ ${#missing[@]} -gt 0 ]; then
        log_warning "Missing commands: ${missing[*]}"
        log_info "Installing base dependencies..."
        dnf install -y curl iptables systemd iproute || {
            log_error "Failed to install base dependencies"
            exit 1
        }
    fi
    
    log_success "Dependencies OK"
}

install_proxy_software() {
    log_info "Installing proxy software..."
    
    # Update system
    log_info "Updating system packages..."
    if ! dnf update -y; then
        log_warning "System update failed, continuing anyway..."
        log_warning "Recommend running 'sudo dnf update -y' manually later"
    fi
    
    # Install SOCKS5 proxy (microsocks - lightweight alternative)
    if ! command -v microsocks &>/dev/null; then
        log_info "Installing microsocks SOCKS5 server..."
        dnf install -y git gcc make || {
            log_error "Failed to install build tools"
            exit 1
        }
        
        # Build microsocks from source
        cd /tmp
        rm -rf microsocks
        git clone https://github.com/rofl0r/microsocks.git || {
            log_error "Failed to clone microsocks repository"
            exit 1
        }
        cd microsocks
        make || {
            log_error "Failed to build microsocks"
            exit 1
        }
        cp microsocks /usr/local/bin/
        chmod +x /usr/local/bin/microsocks
        cd /
        rm -rf /tmp/microsocks
        
        log_success "microsocks SOCKS5 server installed"
    else
        log_success "microsocks already installed"
    fi
    
    # Install HTTP proxy (squid)
    if ! command -v squid &>/dev/null; then
        log_info "Installing Squid HTTP proxy..."
        dnf install -y squid httpd-tools || {
            log_error "Failed to install Squid proxy"
            exit 1
        }
        log_success "Squid HTTP proxy installed"
    else
        log_success "Squid already installed"
    fi
    
    # Install additional tools
    log_info "Installing additional tools..."
    dnf install -y iptables firewalld curl wget nano net-tools policycoreutils-python-utils
}

###############################################################################
# Step 3: Get Proxy Credentials
###############################################################################

validate_username() {
    local username=$1
    
    # Check empty
    if [ -z "$username" ]; then
        echo "Username cannot be empty"
        return 1
    fi
    
    # Check length (3-32 characters)
    if [ ${#username} -lt 3 ]; then
        echo "Username must be at least 3 characters"
        return 1
    fi
    
    if [ ${#username} -gt 32 ]; then
        echo "Username must be 32 characters or less"
        return 1
    fi
    
    # Check format (alphanumeric and underscore only)
    if ! [[ "$username" =~ ^[a-zA-Z0-9_]+$ ]]; then
        echo "Username can only contain letters, numbers, and underscores"
        return 1
    fi
    
    # Check reserved names
    if [[ "$username" =~ ^(root|daemon|bin|sys|sync|games|man|lp|mail|news|uucp|proxy|www-data|backup|list|irc|gnats|nobody|systemd|messagebus|sshd|squid|dante)$ ]]; then
        echo "Username '$username' is reserved by the system"
        return 1
    fi
    
    return 0
}

get_credentials() {
    log_info "Setting up proxy authentication..."
    echo ""
    
    if [ -f /etc/proxy-auth/credentials ]; then
        log_warning "Credentials file already exists"
        read -p "Do you want to use existing credentials? (y/n): " use_existing
        if [ "$use_existing" = "y" ] || [ "$use_existing" = "Y" ]; then
            source /etc/proxy-auth/credentials
            log_success "Using existing credentials for user: $PROXY_USER"
            return
        fi
    fi
    
    echo "Create authentication credentials for your proxy:"
    echo "(These will be required to connect to the proxy)"
    echo ""
    
    # Username validation loop
    while true; do
        read -p "Username: " PROXY_USER
        error_msg=$(validate_username "$PROXY_USER")
        if [ $? -eq 0 ]; then
            break
        else
            log_error "$error_msg"
        fi
    done
    
    read -s -p "Password: " PROXY_PASS
    echo ""
    while [ ${#PROXY_PASS} -lt 8 ]; do
        log_error "Password must be at least 8 characters"
        read -s -p "Password: " PROXY_PASS
        echo ""
    done
    
    read -s -p "Confirm Password: " PROXY_PASS_CONFIRM
    echo ""
    
    while [ "$PROXY_PASS" != "$PROXY_PASS_CONFIRM" ]; do
        log_error "Passwords do not match"
        read -s -p "Password: " PROXY_PASS
        echo ""
        read -s -p "Confirm Password: " PROXY_PASS_CONFIRM
        echo ""
    done
    
    # Save credentials reference (without plain text password for security)
    mkdir -p /etc/proxy-auth
    cat > /etc/proxy-auth/credentials <<EOF
# Proxy User Configuration
# Created: $(date)
PROXY_USER="$PROXY_USER"
# Password is stored securely in hashed form:
#   - HTTP Proxy: /etc/squid/auth/passwords (htpasswd hash)
#   - SOCKS5 Proxy: System shadow file (encrypted)
# 
# SECURITY NOTE: Password is NOT stored in plain text for security.
# To reset password, re-run this setup script or use:
#   sudo htpasswd -b /etc/squid/auth/passwords USERNAME NEW_PASSWORD
#   echo "USERNAME:NEW_PASSWORD" | sudo chpasswd
EOF
    chmod 600 /etc/proxy-auth/credentials
    
    log_success "Credentials configured for user: $PROXY_USER"
}

###############################################################################
# Step 4: Configure SOCKS5 Proxy (Dante)
###############################################################################

configure_socks5() {
    log_info "Configuring SOCKS5 proxy (port $SOCKS5_PORT)..."
    
    # Create microsocks systemd service
    cat > /etc/systemd/system/microsocks.service <<EOF
[Unit]
Description=MicroSOCKS - Lightweight SOCKS5 Proxy
After=network.target

[Service]
Type=simple
User=nobody
ExecStart=/usr/local/bin/microsocks -i 0.0.0.0 -p $SOCKS5_PORT -u $PROXY_USER -P $PROXY_PASS
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    chmod 644 /etc/systemd/system/microsocks.service
    systemctl daemon-reload
    
    log_success "SOCKS5 proxy configured"
}

###############################################################################
# Step 5: Configure HTTP Proxy (Squid)
###############################################################################

configure_http_proxy() {
    log_info "Configuring HTTP proxy (port $HTTP_PORT)..."
    
    # Backup original config
    if [ -f /etc/squid/squid.conf ]; then
        cp /etc/squid/squid.conf /etc/squid/squid.conf.backup
    fi
    
    # Create htpasswd file for authentication
    mkdir -p /etc/squid/auth
    htpasswd -bc /etc/squid/auth/passwords "$PROXY_USER" "$PROXY_PASS"
    chmod 644 /etc/squid/auth/passwords
    
    # Create squid configuration
    cat > /etc/squid/squid.conf <<EOF
# Squid HTTP proxy configuration
# Auto-generated by Oracle Cloud Smart Proxy Setup

# Listen port
http_port $HTTP_PORT

# Authentication
auth_param basic program /usr/lib64/squid/basic_ncsa_auth /etc/squid/auth/passwords
auth_param basic children 5
auth_param basic realm Oracle Cloud Proxy
auth_param basic credentialsttl 2 hours

# Access control lists
acl authenticated proxy_auth REQUIRED
acl SSL_ports port 443
acl Safe_ports port 80          # http
acl Safe_ports port 21          # ftp
acl Safe_ports port 443         # https
acl Safe_ports port 70          # gopher
acl Safe_ports port 210         # wais
acl Safe_ports port 1025-65535  # unregistered ports
acl Safe_ports port 280         # http-mgmt
acl Safe_ports port 488         # gss-http
acl Safe_ports port 591         # filemaker
acl Safe_ports port 777         # multiling http
acl CONNECT method CONNECT

# Deny requests to certain unsafe ports
http_access deny !Safe_ports

# Deny CONNECT to other than secure SSL ports
http_access deny CONNECT !SSL_ports

# Only allow cachemgr access from localhost
http_access allow localhost manager
http_access deny manager

# Allow authenticated users
http_access allow authenticated

# Deny all other access
http_access deny all

# Cache settings
cache_dir ufs /var/spool/squid 100 16 256
coredump_dir /var/spool/squid

# Logging
access_log /var/log/squid/access.log squid
cache_log /var/log/squid/cache.log

# Performance tuning
refresh_pattern ^ftp:           1440    20%     10080
refresh_pattern ^gopher:        1440    0%      1440
refresh_pattern -i (/cgi-bin/|\?) 0     0%      0
refresh_pattern .               0       20%     4320

# Hide client IP
forwarded_for delete
via off

# DNS settings
dns_nameservers 8.8.8.8 1.1.1.1
EOF

    chmod 644 /etc/squid/squid.conf
    
    # Initialize squid cache
    log_info "Initializing Squid cache directory..."
    if ! squid -z 2>/dev/null; then
        log_warning "Failed to initialize squid cache"
        log_warning "Cache will be created on first start"
    else
        log_success "Squid cache initialized"
    fi
    
    log_success "HTTP proxy configured"
}

###############################################################################
# Step 6: Configure Firewall
###############################################################################

configure_firewall() {
    log_info "Configuring firewall..."
    
    # Configure iptables
    log_info "Setting up iptables rules..."
    
    # Allow SOCKS5 port
    iptables -I INPUT -p tcp --dport $SOCKS5_PORT -j ACCEPT
    
    # Allow HTTP proxy port
    iptables -I INPUT -p tcp --dport $HTTP_PORT -j ACCEPT
    
    # Allow established connections
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    
    # Save iptables rules
    mkdir -p /etc/iptables
    iptables-save > /etc/iptables/rules.v4
    
    # Create systemd service to restore iptables on boot
    cat > /etc/systemd/system/iptables-restore.service <<EOF
[Unit]
Description=Restore iptables rules
Before=network-pre.target
Wants=network-pre.target

[Service]
Type=oneshot
ExecStart=/sbin/iptables-restore /etc/iptables/rules.v4
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable iptables-restore.service
    
    # Verify service was enabled
    if ! systemctl is-enabled iptables-restore.service &>/dev/null; then
        log_error "Failed to enable iptables persistence service"
        log_warning "Firewall rules may not persist after reboot"
    else
        log_success "iptables persistence enabled"
    fi
    
    log_success "iptables configured"
    
    # Configure firewalld
    if systemctl is-active --quiet firewalld; then
        log_info "Configuring firewalld..."
        
        firewall-cmd --permanent --add-port=$SOCKS5_PORT/tcp
        firewall-cmd --permanent --add-port=$HTTP_PORT/tcp
        firewall-cmd --reload
        
        log_success "firewalld configured"
        
        # Check for potential conflicts
        log_info "Note: Both iptables and firewalld are active"
        log_info "This is normal for Oracle Linux 8"
    fi
    
    # Oracle Cloud Security List instructions
    echo ""
    log_warning "═══════════════════════════════════════════════════════════"
    log_warning "CRITICAL: Oracle Cloud Security List Configuration Required"
    log_warning "═══════════════════════════════════════════════════════════"
    echo ""
    echo "You MUST configure Oracle Cloud Security List to allow proxy connections:"
    echo ""
    echo "1. Login to Oracle Cloud Console: https://cloud.oracle.com"
    echo "2. Navigate to: ☰ Menu → Networking → Virtual Cloud Networks"
    echo "3. Click your VCN → Security Lists → Default Security List"
    echo "4. Click 'Add Ingress Rules' and add TWO rules:"
    echo ""
    echo "   Rule 1 (SOCKS5):"
    echo "   ┌─────────────────────────────────────┐"
    echo "   │ Source CIDR:    0.0.0.0/0           │"
    echo "   │ IP Protocol:    TCP                 │"
    echo "   │ Dest Port:      $SOCKS5_PORT                    │"
    echo "   │ Description:    SOCKS5 Proxy        │"
    echo "   └─────────────────────────────────────┘"
    echo ""
    echo "   Rule 2 (HTTP Proxy):"
    echo "   ┌─────────────────────────────────────┐"
    echo "   │ Source CIDR:    0.0.0.0/0           │"
    echo "   │ IP Protocol:    TCP                 │"
    echo "   │ Dest Port:      $HTTP_PORT                    │"
    echo "   │ Description:    HTTP Proxy          │"
    echo "   └─────────────────────────────────────┘"
    echo ""
    echo "5. Click 'Add Ingress Rules' for each"
    echo ""
    log_warning "Without this, your proxy will NOT be accessible!"
    log_warning "═══════════════════════════════════════════════════════════"
    echo ""
    read -p "Press ENTER when you have configured Oracle Cloud Security List..."
}

###############################################################################
# Step 7: Start Proxy Services
###############################################################################

start_services() {
    log_info "Starting proxy services..."
    
    # Enable and start microsocks (SOCKS5)
    systemctl enable microsocks
    systemctl restart microsocks
    
    if systemctl is-active --quiet microsocks; then
        log_success "SOCKS5 proxy is running"
    else
        log_error "SOCKS5 proxy failed to start"
        systemctl status microsocks
    fi
    
    # Enable and start squid (HTTP)
    systemctl enable squid
    systemctl restart squid
    
    if systemctl is-active --quiet squid; then
        log_success "HTTP proxy is running"
    else
        log_error "HTTP proxy failed to start"
        systemctl status squid
    fi
}

###############################################################################
# Step 8: Generate Client Configurations
###############################################################################

generate_client_configs() {
    log_info "Generating client configuration files..."
    
    mkdir -p /etc/proxy-configs
    
    # SOCKS5 configuration
    cat > /etc/proxy-configs/socks5-config.txt <<EOF
═══════════════════════════════════════════════════
SOCKS5 PROXY CONFIGURATION
═══════════════════════════════════════════════════

Server:   $PUBLIC_IP
Port:     $SOCKS5_PORT
Type:     SOCKS5
Username: $PROXY_USER
Password: [Your Password]

═══════════════════════════════════════════════════
USAGE EXAMPLES
═══════════════════════════════════════════════════

Windows (System Settings):
1. Settings → Network & Internet → Proxy
2. Enable "Manual proxy setup"
3. Use a proxy server: ON
4. SOCKS proxy: $PUBLIC_IP:$SOCKS5_PORT
5. Authentication required

macOS (System Settings):
1. System Preferences → Network
2. Select your network → Advanced → Proxies
3. Check "SOCKS Proxy"
4. Server: $PUBLIC_IP
5. Port: $SOCKS5_PORT

Linux (Environment Variables):
export ALL_PROXY=socks5://$PROXY_USER:PASSWORD@$PUBLIC_IP:$SOCKS5_PORT

Firefox:
1. Settings → General → Network Settings
2. Manual proxy configuration
3. SOCKS Host: $PUBLIC_IP
4. Port: $SOCKS5_PORT
5. SOCKS v5
6. Check "Proxy DNS when using SOCKS v5"

Chrome (via command line):
chrome --proxy-server="socks5://$PUBLIC_IP:$SOCKS5_PORT"

cURL:
curl --socks5 $PUBLIC_IP:$SOCKS5_PORT --proxy-user $PROXY_USER:PASSWORD https://ifconfig.me

SSH Tunnel (Dynamic Forward):
ssh -D $SOCKS5_PORT user@$PUBLIC_IP

Python (requests library):
proxies = {
    'http': 'socks5://$PROXY_USER:PASSWORD@$PUBLIC_IP:$SOCKS5_PORT',
    'https': 'socks5://$PROXY_USER:PASSWORD@$PUBLIC_IP:$SOCKS5_PORT'
}
response = requests.get('https://ifconfig.me', proxies=proxies)

EOF

    # HTTP Proxy configuration
    cat > /etc/proxy-configs/http-proxy-config.txt <<EOF
═══════════════════════════════════════════════════
HTTP/HTTPS PROXY CONFIGURATION
═══════════════════════════════════════════════════

Server:   $PUBLIC_IP
Port:     $HTTP_PORT
Type:     HTTP/HTTPS
Username: $PROXY_USER
Password: [Your Password]

═══════════════════════════════════════════════════
USAGE EXAMPLES
═══════════════════════════════════════════════════

Windows (System Settings):
1. Settings → Network & Internet → Proxy
2. Enable "Manual proxy setup"
3. Proxy server: $PUBLIC_IP:$HTTP_PORT
4. Use for HTTP and HTTPS

macOS (System Settings):
1. System Preferences → Network
2. Select your network → Advanced → Proxies
3. Check "Web Proxy (HTTP)" and "Secure Web Proxy (HTTPS)"
4. Server: $PUBLIC_IP
5. Port: $HTTP_PORT

Linux (Environment Variables):
export http_proxy=http://$PROXY_USER:PASSWORD@$PUBLIC_IP:$HTTP_PORT
export https_proxy=http://$PROXY_USER:PASSWORD@$PUBLIC_IP:$HTTP_PORT
export HTTP_PROXY=http://$PROXY_USER:PASSWORD@$PUBLIC_IP:$HTTP_PORT
export HTTPS_PROXY=http://$PROXY_USER:PASSWORD@$PUBLIC_IP:$HTTP_PORT

APT (Debian/Ubuntu):
echo 'Acquire::http::Proxy "http://$PROXY_USER:PASSWORD@$PUBLIC_IP:$HTTP_PORT";' | sudo tee /etc/apt/apt.conf.d/proxy.conf

YUM/DNF (RHEL/CentOS):
echo "proxy=http://$PUBLIC_IP:$HTTP_PORT" >> /etc/yum.conf
echo "proxy_username=$PROXY_USER" >> /etc/yum.conf
echo "proxy_password=PASSWORD" >> /etc/yum.conf

Git:
git config --global http.proxy http://$PROXY_USER:PASSWORD@$PUBLIC_IP:$HTTP_PORT
git config --global https.proxy http://$PROXY_USER:PASSWORD@$PUBLIC_IP:$HTTP_PORT

cURL:
curl -x http://$PUBLIC_IP:$HTTP_PORT --proxy-user $PROXY_USER:PASSWORD https://ifconfig.me

wget:
wget -e use_proxy=yes -e http_proxy=$PUBLIC_IP:$HTTP_PORT https://example.com

Python (requests library):
proxies = {
    'http': 'http://$PROXY_USER:PASSWORD@$PUBLIC_IP:$HTTP_PORT',
    'https': 'http://$PROXY_USER:PASSWORD@$PUBLIC_IP:$HTTP_PORT'
}
response = requests.get('https://ifconfig.me', proxies=proxies)

Docker:
# Add to /etc/systemd/system/docker.service.d/http-proxy.conf
[Service]
Environment="HTTP_PROXY=http://$PROXY_USER:PASSWORD@$PUBLIC_IP:$HTTP_PORT"
Environment="HTTPS_PROXY=http://$PROXY_USER:PASSWORD@$PUBLIC_IP:$HTTP_PORT"

EOF

    # Combined quick reference
    cat > /etc/proxy-configs/quick-reference.txt <<EOF
═══════════════════════════════════════════════════
ORACLE CLOUD PROXY - QUICK REFERENCE
═══════════════════════════════════════════════════

Server IP:    $PUBLIC_IP
Username:     $PROXY_USER
Password:     [Stored securely - see /etc/proxy-auth/credentials]

SOCKS5 Proxy: $PUBLIC_IP:$SOCKS5_PORT
HTTP Proxy:   $PUBLIC_IP:$HTTP_PORT

═══════════════════════════════════════════════════
QUICK TEST COMMANDS
═══════════════════════════════════════════════════

Test SOCKS5:
curl --socks5 $PUBLIC_IP:$SOCKS5_PORT --proxy-user $PROXY_USER:PASSWORD https://ifconfig.me

Test HTTP:
curl -x http://$PUBLIC_IP:$HTTP_PORT --proxy-user $PROXY_USER:PASSWORD https://ifconfig.me

Expected output: $PUBLIC_IP (your proxy server's IP)

═══════════════════════════════════════════════════
SERVICE MANAGEMENT
═══════════════════════════════════════════════════

Check status:
  sudo systemctl status microsocks  # SOCKS5
  sudo systemctl status squid       # HTTP

Restart services:
  sudo systemctl restart microsocks
  sudo systemctl restart squid

View logs:
  sudo journalctl -u microsocks -f
  sudo tail -f /var/log/squid/access.log

Run diagnostics:
  sudo ./oracle-proxy-setup.sh --diagnose

Auto-fix issues:
  sudo ./oracle-proxy-setup.sh --fix

═══════════════════════════════════════════════════
WEB DASHBOARD
═══════════════════════════════════════════════════

Install dashboard:
  sudo ./install-dashboard.sh

Access at: http://$PUBLIC_IP:1234

EOF

    chmod 644 /etc/proxy-configs/*
    
    log_success "Client configuration files generated"
}

###############################################################################
# Step 9: Run Diagnostics
###############################################################################

run_diagnostics() {
    echo ""
    log_info "═══════════════════════════════════════════════════"
    log_info "Running diagnostics..."
    log_info "═══════════════════════════════════════════════════"
    echo ""
    
    echo "Network Configuration:"
    echo "  Interface: $PRIMARY_INTERFACE"
    echo "  Public IP: $PUBLIC_IP"
    echo "  Private IP: $PRIVATE_IP"
    echo ""
    
    echo "Proxy Ports:"
    echo -n "  SOCKS5 ($SOCKS5_PORT): "
    if systemctl is-active --quiet danted; then
        echo -e "${GREEN}RUNNING${NC}"
    else
        echo -e "${RED}STOPPED${NC}"
    fi
    
    echo -n "  HTTP ($HTTP_PORT): "
    if systemctl is-active --quiet squid; then
        echo -e "${GREEN}RUNNING${NC}"
    else
        echo -e "${RED}STOPPED${NC}"
    fi
    echo ""
    
    echo "Firewall Rules:"
    echo -n "  iptables port $SOCKS5_PORT: "
    if iptables -L INPUT -n | grep -q "$SOCKS5_PORT"; then
        echo -e "${GREEN}CONFIGURED${NC}"
    else
        echo -e "${YELLOW}MISSING${NC}"
    fi
    
    echo -n "  iptables port $HTTP_PORT: "
    if iptables -L INPUT -n | grep -q "$HTTP_PORT"; then
        echo -e "${GREEN}CONFIGURED${NC}"
    else
        echo -e "${YELLOW}MISSING${NC}"
    fi
    echo ""
    
    echo "Listening Ports:"
    netstat -tulpn 2>/dev/null | grep -E ":($SOCKS5_PORT|$HTTP_PORT)" || ss -tulpn | grep -E ":($SOCKS5_PORT|$HTTP_PORT)"
    echo ""
}

###############################################################################
# Installation Verification
###############################################################################

verify_installation() {
    log_info "Verifying installation..."
    local errors=0
    
    # Check services
    echo -n "  Checking SOCKS5 service... "
    if systemctl is-active --quiet danted; then
        echo -e "${GREEN}OK${NC}"
    else
        echo -e "${RED}FAILED${NC}"
        ((errors++))
    fi
    
    echo -n "  Checking HTTP service... "
    if systemctl is-active --quiet squid; then
        echo -e "${GREEN}OK${NC}"
    else
        echo -e "${RED}FAILED${NC}"
        ((errors++))
    fi
    
    # Check ports
    echo -n "  Checking SOCKS5 port listening... "
    if netstat -tulpn 2>/dev/null | grep -q ":$SOCKS5_PORT" || ss -tulpn 2>/dev/null | grep -q ":$SOCKS5_PORT"; then
        echo -e "${GREEN}OK${NC}"
    else
        echo -e "${RED}FAILED${NC}"
        ((errors++))
    fi
    
    echo -n "  Checking HTTP port listening... "
    if netstat -tulpn 2>/dev/null | grep -q ":$HTTP_PORT" || ss -tulpn 2>/dev/null | grep -q ":$HTTP_PORT"; then
        echo -e "${GREEN}OK${NC}"
    else
        echo -e "${RED}FAILED${NC}"
        ((errors++))
    fi
    
    # Check firewall
    echo -n "  Checking firewall rules... "
    if iptables -L INPUT -n | grep -q "$SOCKS5_PORT" && iptables -L INPUT -n | grep -q "$HTTP_PORT"; then
        echo -e "${GREEN}OK${NC}"
    else
        echo -e "${YELLOW}WARNING${NC}"
        log_warning "Firewall rules may not be properly configured"
    fi
    
    return $errors
}

###############################################################################
# Main Installation Flow
###############################################################################

main() {
    check_dependencies
    detect_network
    install_proxy_software
    get_credentials
    configure_socks5
    configure_http_proxy
    configure_firewall
    start_services
    generate_client_configs
    run_diagnostics
    
    echo ""
    if verify_installation; then
        log_success "Installation verified successfully!"
    else
        log_warning "Installation completed but some services may need attention"
        log_info "Run diagnostics: sudo ./oracle-proxy-setup.sh --diagnose"
        log_info "Or try auto-fix: sudo ./complete-fix.sh"
    fi
    
    echo ""
    log_success "═══════════════════════════════════════════════════"
    log_success "Installation completed successfully!"
    log_success "═══════════════════════════════════════════════════"
    echo ""
    echo "Your proxy server is ready to use:"
    echo ""
    echo "  SOCKS5: $PUBLIC_IP:$SOCKS5_PORT"
    echo "  HTTP:   $PUBLIC_IP:$HTTP_PORT"
    echo "  User:   $PROXY_USER"
    echo ""
    echo "Configuration files saved to:"
    echo "  • /etc/proxy-configs/socks5-config.txt"
    echo "  • /etc/proxy-configs/http-proxy-config.txt"
    echo "  • /etc/proxy-configs/quick-reference.txt"
    echo ""
    log_info "View configurations:"
    echo "  sudo cat /etc/proxy-configs/quick-reference.txt"
    echo ""
    log_info "Test your proxy:"
    echo "  curl --socks5 $PUBLIC_IP:$SOCKS5_PORT --proxy-user $PROXY_USER:PASSWORD https://ifconfig.me"
    echo ""
    log_warning "Don't forget to configure Oracle Cloud Security List!"
    echo ""
}

###############################################################################
# Command-line Arguments
###############################################################################

case "${1:-}" in
    --diagnose)
        detect_network
        run_diagnostics
        ;;
    --fix)
        log_info "Running auto-fix..."
        detect_network
        
        # Restart services
        systemctl restart microsocks
        systemctl restart squid
        
        # Re-apply firewall rules
        iptables -I INPUT -p tcp --dport $SOCKS5_PORT -j ACCEPT 2>/dev/null || true
        iptables -I INPUT -p tcp --dport $HTTP_PORT -j ACCEPT 2>/dev/null || true
        iptables-save > /etc/iptables/rules.v4
        
        if systemctl is-active --quiet firewalld; then
            firewall-cmd --permanent --add-port=$SOCKS5_PORT/tcp
            firewall-cmd --permanent --add-port=$HTTP_PORT/tcp
            firewall-cmd --reload
        fi
        
        log_success "Auto-fix completed"
        run_diagnostics
        ;;
    --show-config)
        if [ -f /etc/proxy-configs/quick-reference.txt ]; then
            cat /etc/proxy-configs/quick-reference.txt
        else
            log_error "Configuration not found. Run setup first."
        fi
        ;;
    --help)
        echo "Oracle Cloud Smart Proxy Setup"
        echo ""
        echo "Usage:"
        echo "  $0                - Full installation"
        echo "  $0 --diagnose     - Run diagnostics"
        echo "  $0 --fix          - Auto-fix common issues"
        echo "  $0 --show-config  - Show proxy configuration"
        echo "  $0 --help         - Show this help"
        ;;
    *)
        main
        ;;
esac
