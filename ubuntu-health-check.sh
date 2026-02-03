#!/bin/bash

###############################################################################
# Ubuntu Cloud Proxy Health Check Script
# Comprehensive verification of proxy setup
###############################################################################

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo ""
echo -e "${BLUE}╔════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║   Ubuntu Cloud Proxy Health Check             ║${NC}"
echo -e "${BLUE}╔════════════════════════════════════════════════╗${NC}"
echo ""

PASS=0
FAIL=0
WARN=0

check() {
    local name=$1
    local command=$2
    local expected=$3
    
    echo -n "Checking $name... "
    
    if eval "$command" 2>/dev/null | grep -q "$expected"; then
        echo -e "${GREEN}✓ PASS${NC}"
        ((PASS++))
        return 0
    else
        echo -e "${RED}✗ FAIL${NC}"
        ((FAIL++))
        return 1
    fi
}

warn_check() {
    local name=$1
    local command=$2
    local expected=$3
    
    echo -n "Checking $name... "
    
    if eval "$command" 2>/dev/null | grep -q "$expected"; then
        echo -e "${GREEN}✓ PASS${NC}"
        ((PASS++))
        return 0
    else
        echo -e "${YELLOW}⚠ WARNING${NC}"
        ((WARN++))
        return 1
    fi
}

# Core checks
echo -e "${BLUE}═══ Service Status ═══${NC}"

# Check if binaries are installed first
if ! command -v microsocks &>/dev/null; then
    echo -e "${RED}✗ Microsocks not installed${NC}"
    ((FAIL++))
else
    check "Microsocks (SOCKS5) installed" "command -v microsocks" "microsocks"
fi

check "Squid (HTTP) installed" "command -v squid" "squid"

# Only check service status if installed
if command -v microsocks &>/dev/null; then
    check "Microsocks service running" "systemctl is-active microsocks" "active"
else
    echo -e "${RED}✗ Cannot check microsocks service - not installed${NC}"
    ((FAIL++))
fi

check "Squid service running" "systemctl is-active squid" "active"

echo ""
echo -e "${BLUE}═══ Network Configuration ═══${NC}"

# Get interface
INTERFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
if [ -z "$INTERFACE" ]; then
    echo -e "${RED}✗ Cannot detect network interface${NC}"
    ((FAIL++))
else
    echo -e "Primary interface: ${GREEN}$INTERFACE${NC}"
    ((PASS++))
fi

# Get public IP
PUBLIC_IP=$(curl -s -m 5 ifconfig.me 2>/dev/null)
if [ -z "$PUBLIC_IP" ]; then
    echo -e "${YELLOW}⚠ Cannot detect public IP (may be network issue)${NC}"
    ((WARN++))
else
    echo -e "Public IP: ${GREEN}$PUBLIC_IP${NC}"
    ((PASS++))
fi

echo ""
echo -e "${BLUE}═══ Firewall Rules (iptables) ═══${NC}"
check "Port 1080 allowed" "iptables -L INPUT -n" "1080"
check "Port 8888 allowed" "iptables -L INPUT -n" "8888"

echo ""
echo -e "${BLUE}═══ Listening Ports ═══${NC}"
check "SOCKS5 listening on 1080" "netstat -tulpn 2>/dev/null || ss -tulpn" ":1080"
check "HTTP listening on 8888" "netstat -tulpn 2>/dev/null || ss -tulpn" ":8888"

echo ""
echo -e "${BLUE}═══ Configuration Files ═══${NC}"
check "Microsocks service exists" "test -f /etc/systemd/system/microsocks.service && echo exists" "exists"
check "Squid config exists" "test -f /etc/squid/squid.conf && echo exists" "exists"
check "Proxy auth exists" "test -f /etc/squid/auth/passwords && echo exists" "exists"

echo ""
echo -e "${BLUE}═══ Authentication ═══${NC}"
if [ -f /etc/squid/auth/passwords ]; then
    USER_COUNT=$(wc -l < /etc/squid/auth/passwords)
    echo -e "Configured users: ${GREEN}$USER_COUNT${NC}"
    ((PASS++))
else
    echo -e "${RED}✗ No authentication file found${NC}"
    ((FAIL++))
fi

echo ""
echo -e "${BLUE}═══ AppArmor Status ═══${NC}"
if command -v aa-status &>/dev/null; then
    if aa-status --enabled 2>/dev/null; then
        echo -e "AppArmor: ${GREEN}Enabled (normal for Ubuntu)${NC}"
        ((PASS++))
    else
        echo -e "AppArmor: ${YELLOW}Disabled${NC}"
        ((WARN++))
    fi
else
    echo -e "AppArmor: ${GREEN}Not installed${NC}"
    ((PASS++))
fi

echo ""
echo -e "${BLUE}═══ Active Connections ═══${NC}"

# SOCKS5 connections
SOCKS5_CONN=$(netstat -an 2>/dev/null | grep -c ":1080.*ESTABLISHED" || echo "0")
echo -e "SOCKS5 active connections: ${GREEN}$SOCKS5_CONN${NC}"

# HTTP connections
HTTP_CONN=$(netstat -an 2>/dev/null | grep -c ":8888.*ESTABLISHED" || echo "0")
echo -e "HTTP active connections: ${GREEN}$HTTP_CONN${NC}"

# Show recent connections
echo ""
echo -e "${BLUE}═══ Recent Connection IPs ═══${NC}"
if [ -f /var/log/squid/access.log ]; then
    echo "Last 5 HTTP proxy accesses:"
    tail -n 5 /var/log/squid/access.log | awk '{print $3}' | sort -u
else
    echo -e "${YELLOW}No HTTP access logs found${NC}"
fi

echo ""
echo -e "${BLUE}═══ Persistence Checks ═══${NC}"
check "Microsocks auto-start enabled" "systemctl is-enabled microsocks" "enabled"
check "Squid auto-start enabled" "systemctl is-enabled squid" "enabled"

# Check iptables persistence
if command -v netfilter-persistent &>/dev/null; then
    echo -e "iptables persistence: ${GREEN}netfilter-persistent installed${NC}"
    ((PASS++))
else
    echo -e "iptables persistence: ${YELLOW}Not installed (may not persist reboot)${NC}"
    ((WARN++))
fi

# Check UFW
echo ""
echo -e "${BLUE}═══ UFW Status ═══${NC}"
if systemctl is-active --quiet ufw; then
    echo -e "UFW: ${GREEN}Active${NC}"
    if ufw status 2>/dev/null | grep -q "1080/tcp"; then
        echo -e "Port 1080/tcp: ${GREEN}Allowed${NC}"
        ((PASS++))
    else
        echo -e "Port 1080/tcp: ${YELLOW}Not configured${NC}"
        ((WARN++))
    fi
    
    if ufw status 2>/dev/null | grep -q "8888/tcp"; then
        echo -e "Port 8888/tcp: ${GREEN}Allowed${NC}"
        ((PASS++))
    else
        echo -e "Port 8888/tcp: ${YELLOW}Not configured${NC}"
        ((WARN++))
    fi
else
    echo -e "UFW: ${YELLOW}Not active (using iptables only)${NC}"
    ((WARN++))
fi

# Summary
echo ""
echo -e "${BLUE}╔════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║   Health Check Summary                         ║${NC}"
echo -e "${BLUE}╔════════════════════════════════════════════════╗${NC}"
echo ""
echo -e "Passed:   ${GREEN}$PASS${NC}"
echo -e "Failed:   ${RED}$FAIL${NC}"
echo -e "Warnings: ${YELLOW}$WARN${NC}"
echo ""

# Recommendations
if [ $FAIL -eq 0 ] && [ $WARN -eq 0 ]; then
    echo -e "${GREEN}✓ All checks passed! Your proxy is healthy.${NC}"
    echo ""
    echo -e "${BLUE}Connection Information:${NC}"
    if [ ! -z "$PUBLIC_IP" ]; then
        echo "  SOCKS5: $PUBLIC_IP:1080"
        echo "  HTTP:   $PUBLIC_IP:8888"
        echo ""
        echo "Test with:"
        echo "  curl --socks5 $PUBLIC_IP:1080 --proxy-user USER:PASS https://ifconfig.me"
    fi
    echo ""
    echo -e "${BLUE}Next Steps:${NC}"
    echo "1. Configure cloud security groups (if not done)"
    echo "2. Test connectivity from your device"
    echo "3. Install dashboard: sudo ./ubuntu-install-dashboard.sh"
    exit 0
    
elif [ $FAIL -eq 0 ]; then
    echo -e "${YELLOW}✓ Critical checks passed, but some warnings found.${NC}"
    echo ""
    echo -e "${YELLOW}Warnings are usually not critical, but recommended to fix:${NC}"
    echo "• Run: sudo ./ubuntu-complete-fix.sh"
    echo "• Check cloud security group configuration"
    echo ""
    exit 0
    
else
    echo -e "${RED}✗ Some critical checks failed${NC}"
    echo ""
    echo -e "${YELLOW}Recommended Actions:${NC}"
    
    if ! systemctl is-active --quiet microsocks; then
        echo "• Start SOCKS5: sudo systemctl start microsocks"
    fi
    
    if ! systemctl is-active --quiet squid; then
        echo "• Start HTTP proxy: sudo systemctl start squid"
    fi
    
    echo "• Run auto-fix: sudo ./ubuntu-complete-fix.sh"
    echo "• Check logs:"
    echo "    sudo journalctl -u microsocks -n 20"
    echo "    sudo journalctl -u squid -n 20"
    echo ""
    
    echo -e "${BLUE}Detailed Diagnostics:${NC}"
    echo ""
    
    echo "Service Status:"
    systemctl status microsocks --no-pager -n 3 2>/dev/null || echo "  Microsocks not installed"
    systemctl status squid --no-pager -n 3 2>/dev/null || echo "  Squid not installed"
    
    echo ""
    echo "Network Ports:"
    netstat -tulpn 2>/dev/null | grep -E ":1080|:8888" || echo "  No proxy ports listening"
    
    echo ""
    exit 1
fi
