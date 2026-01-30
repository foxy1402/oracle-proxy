#!/bin/bash

###############################################################################
# Oracle Cloud Proxy Complete Fix Script
# Fixes common proxy connection issues automatically
###############################################################################

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}════════════════════════════════════════${NC}"
echo -e "${BLUE}Oracle Cloud Proxy Complete Fix${NC}"
echo -e "${BLUE}════════════════════════════════════════${NC}"
echo ""

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}This script must be run as root${NC}"
   exit 1
fi

SOCKS5_PORT=1080
HTTP_PORT=8888

# Get network interface
echo -e "${BLUE}[1/8]${NC} Detecting network interface..."
INTERFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
if [ -z "$INTERFACE" ]; then
    echo -e "${RED}Could not detect network interface${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Interface: $INTERFACE${NC}"

# Fix SELinux if blocking
echo -e "${BLUE}[2/8]${NC} Checking SELinux..."
if command -v getenforce &>/dev/null; then
    SELINUX_STATUS=$(getenforce)
    if [ "$SELINUX_STATUS" = "Enforcing" ]; then
        echo -e "${YELLOW}! SELinux is Enforcing, configuring policies...${NC}"
        
        # Try to add proper SELinux policies first
        if command -v semanage &>/dev/null; then
            # Allow proxy ports
            semanage port -a -t http_cache_port_t -p tcp 8888 2>/dev/null || \
            semanage port -m -t http_cache_port_t -p tcp 8888 2>/dev/null || true
            
            semanage port -a -t socks_port_t -p tcp 1080 2>/dev/null || \
            semanage port -m -t socks_port_t -p tcp 1080 2>/dev/null || true
            
            echo -e "${GREEN}✓ SELinux policies configured${NC}"
        else
            # Only set permissive if semanage not available
            echo -e "${YELLOW}! semanage not found, setting SELinux to Permissive${NC}"
            echo -e "${YELLOW}! For better security, install: dnf install policycoreutils-python-utils${NC}"
            setenforce 0
            sed -i 's/SELINUX=enforcing/SELINUX=permissive/' /etc/selinux/config
            echo -e "${YELLOW}✓ SELinux set to Permissive${NC}"
        fi
    else
        echo -e "${GREEN}✓ SELinux: $SELINUX_STATUS${NC}"
    fi
else
    echo -e "${GREEN}✓ SELinux not installed${NC}"
fi

# Clear old firewall rules
echo -e "${BLUE}[3/8]${NC} Clearing old firewall rules..."
iptables -D INPUT -p tcp --dport $SOCKS5_PORT -j ACCEPT 2>/dev/null || true
iptables -D INPUT -p tcp --dport $HTTP_PORT -j ACCEPT 2>/dev/null || true
echo -e "${GREEN}✓ Old rules cleared${NC}"

# Add new firewall rules
echo -e "${BLUE}[4/8]${NC} Adding firewall rules..."
iptables -I INPUT -p tcp --dport $SOCKS5_PORT -j ACCEPT
iptables -I INPUT -p tcp --dport $HTTP_PORT -j ACCEPT
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Save rules
mkdir -p /etc/iptables
iptables-save > /etc/iptables/rules.v4
echo -e "${GREEN}✓ Firewall rules added${NC}"

# Configure firewalld
echo -e "${BLUE}[5/8]${NC} Configuring firewalld..."
if systemctl is-active --quiet firewalld; then
    firewall-cmd --permanent --add-port=$SOCKS5_PORT/tcp 2>/dev/null || true
    firewall-cmd --permanent --add-port=$HTTP_PORT/tcp 2>/dev/null || true
    firewall-cmd --reload
    echo -e "${GREEN}✓ firewalld configured${NC}"
else
    echo -e "${YELLOW}! firewalld not active${NC}"
fi

# Fix dante configuration permissions
echo -e "${BLUE}[6/8]${NC} Fixing dante configuration..."
if [ -f /etc/danted.conf ]; then
    chmod 644 /etc/danted.conf
    echo -e "${GREEN}✓ Dante config permissions fixed${NC}"
fi

# Fix squid configuration and cache
echo -e "${BLUE}[7/8]${NC} Fixing squid configuration..."
if [ -f /etc/squid/squid.conf ]; then
    chmod 644 /etc/squid/squid.conf
    
    # Fix squid cache permissions
    chown -R squid:squid /var/spool/squid
    chown -R squid:squid /var/log/squid
    
    # Recreate cache directory if needed
    if [ ! -d /var/spool/squid/00 ]; then
        squid -z 2>/dev/null || true
    fi
    
    echo -e "${GREEN}✓ Squid config fixed${NC}"
fi

# Restart services
echo -e "${BLUE}[8/8]${NC} Restarting proxy services..."

systemctl daemon-reload

# Restart dante (SOCKS5)
systemctl restart danted
sleep 2
if systemctl is-active --quiet danted; then
    echo -e "${GREEN}✓ SOCKS5 proxy restarted${NC}"
else
    echo -e "${RED}✗ SOCKS5 failed to start${NC}"
    journalctl -u danted -n 10 --no-pager
fi

# Restart squid (HTTP)
systemctl restart squid
sleep 2
if systemctl is-active --quiet squid; then
    echo -e "${GREEN}✓ HTTP proxy restarted${NC}"
else
    echo -e "${RED}✗ HTTP proxy failed to start${NC}"
    journalctl -u squid -n 10 --no-pager
fi

# Verification
echo ""
echo -e "${BLUE}════════════════════════════════════════${NC}"
echo -e "${BLUE}Verification${NC}"
echo -e "${BLUE}════════════════════════════════════════${NC}"
echo ""

# Check services
echo -n "SOCKS5 Service: "
if systemctl is-active --quiet danted; then
    echo -e "${GREEN}RUNNING${NC}"
else
    echo -e "${RED}STOPPED${NC}"
fi

echo -n "HTTP Service: "
if systemctl is-active --quiet squid; then
    echo -e "${GREEN}RUNNING${NC}"
else
    echo -e "${RED}STOPPED${NC}"
fi

# Check ports
echo ""
echo "Listening Ports:"
netstat -tulpn 2>/dev/null | grep -E ":($SOCKS5_PORT|$HTTP_PORT)" || ss -tulpn | grep -E ":($SOCKS5_PORT|$HTTP_PORT)"

# Check firewall
echo ""
echo -n "Firewall port $SOCKS5_PORT: "
if iptables -L INPUT -n | grep -q "$SOCKS5_PORT"; then
    echo -e "${GREEN}OPEN${NC}"
else
    echo -e "${RED}BLOCKED${NC}"
fi

echo -n "Firewall port $HTTP_PORT: "
if iptables -L INPUT -n | grep -q "$HTTP_PORT"; then
    echo -e "${GREEN}OPEN${NC}"
else
    echo -e "${RED}BLOCKED${NC}"
fi

echo ""
echo -e "${BLUE}════════════════════════════════════════${NC}"
echo -e "${BLUE}Oracle Cloud Security List Reminder${NC}"
echo -e "${BLUE}════════════════════════════════════════${NC}"
echo ""
echo -e "${YELLOW}Don't forget to configure Oracle Cloud Security List!${NC}"
echo ""
echo "1. Login to Oracle Cloud Console"
echo "2. Go to: Networking → Virtual Cloud Networks"
echo "3. Add Ingress Rules for:"
echo "   - TCP port $SOCKS5_PORT (SOCKS5)"
echo "   - TCP port $HTTP_PORT (HTTP)"
echo ""

echo -e "${GREEN}════════════════════════════════════════${NC}"
echo -e "${GREEN}Fix completed!${NC}"
echo -e "${GREEN}════════════════════════════════════════${NC}"
echo ""
echo "Test your proxy:"
PUBLIC_IP=$(curl -s ifconfig.me)
echo "  curl --socks5 $PUBLIC_IP:$SOCKS5_PORT --proxy-user USERNAME:PASSWORD https://ifconfig.me"
echo ""
