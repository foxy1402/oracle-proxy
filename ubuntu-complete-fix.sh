#!/bin/bash

###############################################################################
# Ubuntu Cloud Proxy Complete Fix Script
# Fixes common proxy connection issues automatically
###############################################################################

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo ""
echo -e "${BLUE}╔════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║   Ubuntu Cloud Proxy Complete Fix             ║${NC}"
echo -e "${BLUE}║   Automatically repairs common issues          ║${NC}"
echo -e "${BLUE}╔════════════════════════════════════════════════╗${NC}"
echo ""

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}[ERROR]${NC} This script must be run as root"
   echo "Please run: sudo ./ubuntu-complete-fix.sh"
   exit 1
fi

SOCKS5_PORT=1080
HTTP_PORT=8888

# Get network interface
echo -e "${BLUE}[1/6]${NC} Detecting network interface..."
INTERFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
if [ -z "$INTERFACE" ]; then
    echo -e "${RED}Could not detect network interface${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Interface: $INTERFACE${NC}"

# Check AppArmor (Ubuntu's security module)
echo -e "${BLUE}[2/6]${NC} Checking AppArmor..."
if command -v aa-status &>/dev/null; then
    if aa-status --enabled 2>/dev/null; then
        echo -e "${GREEN}✓ AppArmor is enabled (this is normal for Ubuntu)${NC}"
        # AppArmor rarely blocks proxies, but we can check
        if aa-status 2>/dev/null | grep -q squid; then
            echo -e "${YELLOW}! Squid has AppArmor profile${NC}"
        fi
    fi
else
    echo -e "${GREEN}✓ AppArmor not found${NC}"
fi

# Clear old firewall rules
echo -e "${BLUE}[3/6]${NC} Clearing old firewall rules..."
iptables -D INPUT -p tcp --dport $SOCKS5_PORT -j ACCEPT 2>/dev/null || true
iptables -D INPUT -p tcp --dport $HTTP_PORT -j ACCEPT 2>/dev/null || true
echo -e "${GREEN}✓ Old rules cleared${NC}"

# Add new firewall rules
echo -e "${BLUE}[4/6]${NC} Adding firewall rules..."
iptables -I INPUT -p tcp --dport $SOCKS5_PORT -j ACCEPT
iptables -I INPUT -p tcp --dport $HTTP_PORT -j ACCEPT
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Save rules
if command -v netfilter-persistent &>/dev/null; then
    netfilter-persistent save
    echo -e "${GREEN}✓ Firewall rules saved with netfilter-persistent${NC}"
else
    echo -e "${YELLOW}! Installing iptables-persistent...${NC}"
    echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
    echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
    apt-get install -y iptables-persistent
    netfilter-persistent save
    echo -e "${GREEN}✓ Firewall rules saved${NC}"
fi

# Configure UFW if active
if systemctl is-active --quiet ufw; then
    echo -e "${BLUE}[5/6]${NC} Configuring UFW..."
    ufw allow $SOCKS5_PORT/tcp comment 'SOCKS5 Proxy' 2>/dev/null || true
    ufw allow $HTTP_PORT/tcp comment 'HTTP Proxy' 2>/dev/null || true
    echo -e "${GREEN}✓ UFW configured${NC}"
else
    echo -e "${BLUE}[5/6]${NC} UFW not active (using iptables only)"
fi

# Fix squid configuration and cache
echo -e "${BLUE}[6/6]${NC} Fixing squid configuration..."
if [ -f /etc/squid/squid.conf ]; then
    chmod 644 /etc/squid/squid.conf
    
    # Ubuntu uses 'proxy' user, not 'squid' user
    SQUID_USER="proxy"
    if ! id -u proxy &>/dev/null; then
        SQUID_USER="squid"
    fi
    
    # Fix squid cache permissions
    chown -R $SQUID_USER:$SQUID_USER /var/spool/squid 2>/dev/null || true
    chown -R $SQUID_USER:$SQUID_USER /var/log/squid 2>/dev/null || true
    
    # Recreate cache directory if needed
    if [ ! -d /var/spool/squid/00 ]; then
        squid -z 2>/dev/null || true
    fi
    
    echo -e "${GREEN}✓ Squid config fixed${NC}"
fi

# Restart services
echo -e "${BLUE}Restarting proxy services...${NC}"

systemctl daemon-reload

# Restart microsocks (SOCKS5)
systemctl restart microsocks
sleep 2
if systemctl is-active --quiet microsocks; then
    echo -e "${GREEN}✓ SOCKS5 proxy restarted${NC}"
else
    echo -e "${RED}✗ SOCKS5 failed to start${NC}"
    journalctl -u microsocks -n 10 --no-pager
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
if systemctl is-active --quiet microsocks; then
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
echo -e "${BLUE}Cloud Security Group Reminder${NC}"
echo -e "${BLUE}════════════════════════════════════════${NC}"
echo ""
echo -e "${YELLOW}Don't forget to configure cloud security groups!${NC}"
echo ""
echo "Add inbound rules for:"
echo "   - TCP port $SOCKS5_PORT (SOCKS5)"
echo "   - TCP port $HTTP_PORT (HTTP)"
echo ""
echo -e "${YELLOW}For Ubuntu instances on AWS/GCP/Azure/Oracle Cloud:${NC}"
echo "Security groups MUST be configured in cloud console."
echo ""

echo ""
echo -e "${GREEN}╔════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║   Fix completed successfully!                  ║${NC}"
echo -e "${GREEN}╔════════════════════════════════════════════════╗${NC}"
echo ""
echo "Your proxy services have been repaired."
echo ""
echo -e "${BLUE}Test your proxy:${NC}"
PUBLIC_IP=$(curl -s -m 5 ifconfig.me || echo "YOUR_SERVER_IP")
echo "  curl --socks5 $PUBLIC_IP:$SOCKS5_PORT --proxy-user USERNAME:PASSWORD https://ifconfig.me"
echo ""
echo -e "${YELLOW}Next steps:${NC}"
echo "  1. Run health check: sudo ./ubuntu-health-check.sh"
echo "  2. Test from your device"
echo "  3. Check cloud security group settings if still not working"
echo ""
