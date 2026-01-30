# Oracle Cloud Proxy - Troubleshooting Guide

## Quick Diagnostic Flowchart

```
Can you connect to your proxy at all?
│
├─ NO → Problem 1 (Connection Refused)
│
└─ YES → Does authentication work?
    │
    ├─ NO → Problem 2 (Authentication Failed)
    │
    └─ YES → Is speed acceptable?
        │
        ├─ NO → Problem 3 (Slow Performance)
        │
        └─ YES → Does it work reliably?
            │
            ├─ NO → Problem 4 (Intermittent Failures)
            │
            └─ YES → 🎉 Everything works!
```

---

## Problem 1: Connection Refused / Cannot Connect

### Symptoms
- `Connection refused` error
- `Connection timeout` error
- Cannot establish connection to proxy at all
- `curl: (7) Failed to connect to port 1080: Connection refused`

### Diagnosis

**Step 1: Check if services are running**
```bash
sudo systemctl status danted
sudo systemctl status squid
```

**Expected:** Both should show "active (running)" in green

**If not running:**
```bash
# Start services
sudo systemctl start danted
sudo systemctl start squid

# Enable auto-start
sudo systemctl enable danted
sudo systemctl enable squid
```

---

**Step 2: Check if ports are listening**
```bash
sudo netstat -tulpn | grep -E "1080|8888"
```

**Expected output:**
```
tcp  0  0.0.0.0:1080  0.0.0.0:*  LISTEN  1234/sockd
tcp  0  0.0.0.0:8888  0.0.0.0:*  LISTEN  5678/squid
```

**If nothing appears:**
- Services may have failed to start
- Configuration error
- Run: `sudo ./complete-fix.sh`

---

**Step 3: Check firewall rules**
```bash
sudo iptables -L INPUT -n | grep -E "1080|8888"
```

**Expected:** Lines showing ports 1080 and 8888 allowed

**If not shown:**
```bash
# Add rules
sudo iptables -I INPUT -p tcp --dport 1080 -j ACCEPT
sudo iptables -I INPUT -p tcp --dport 8888 -j ACCEPT

# Save rules
sudo mkdir -p /etc/iptables
sudo iptables-save > /etc/iptables/rules.v4
```

---

**Step 4: Check Oracle Cloud Security List**

⚠️ **This is the #1 cause of connection issues!**

1. Login to https://cloud.oracle.com
2. Go to: Networking → Virtual Cloud Networks
3. Click your VCN → Security Lists → Default Security List
4. Look for ingress rules with:
   - TCP port 1080 (SOCKS5)
   - TCP port 8888 (HTTP)
   - Source: 0.0.0.0/0

**If missing:** Add them following the main README.md instructions

---

**Step 5: Check SELinux**
```bash
getenforce
```

**If shows "Enforcing":**
```bash
# Temporarily set to permissive
sudo setenforce 0

# Test proxy again
# If it works, make permanent:
sudo sed -i 's/SELINUX=enforcing/SELINUX=permissive/' /etc/selinux/config
```

---

### Complete Fix

If diagnosis doesn't help, run the auto-fix:

```bash
sudo ./complete-fix.sh
```

This will:
- Restart all services
- Fix firewall rules
- Fix SELinux if needed
- Check configurations
- Apply all necessary fixes

---

## Problem 2: Authentication Failed

### Symptoms
- `407 Proxy Authentication Required`
- `Authentication failed`
- Can connect but immediately rejected
- Browser asks for credentials but rejects them

### Diagnosis

**Step 1: Verify credentials**
```bash
sudo cat /etc/proxy-auth/credentials
```

This shows your actual username and password. Make sure you're using exactly these.

---

**Step 2: Check user exists in all systems**

**For Squid (HTTP):**
```bash
sudo cat /etc/squid/auth/passwords
```

Should show: `username:hashedpassword`

**For Dante (SOCKS5):**
```bash
id USERNAME
```

Should show user info. If not found:
```bash
sudo useradd -r -s /bin/false USERNAME
echo "USERNAME:PASSWORD" | sudo chpasswd
```

---

**Step 3: Verify password hash**

Re-add user to ensure correct password:

```bash
# Replace with your actual username and password
USERNAME="youruser"
PASSWORD="yourpassword"

# Add to Squid
sudo htpasswd -b /etc/squid/auth/passwords $USERNAME $PASSWORD

# Add to system (for Dante)
if ! id -u $USERNAME &>/dev/null; then
    sudo useradd -r -s /bin/false $USERNAME
fi
echo "$USERNAME:$PASSWORD" | sudo chpasswd

# Restart services
sudo systemctl restart danted
sudo systemctl restart squid
```

---

**Step 4: Check Squid auth configuration**
```bash
sudo grep -A 2 "auth_param" /etc/squid/squid.conf
```

**Expected:**
```
auth_param basic program /usr/lib64/squid/basic_ncsa_auth /etc/squid/auth/passwords
auth_param basic children 5
auth_param basic realm Oracle Cloud Proxy
```

**If different:** Re-run setup script or manually edit config

---

**Step 5: Check file permissions**
```bash
ls -la /etc/squid/auth/passwords
```

**Should show:** `-rw-r--r--` or similar (readable by squid)

**If wrong:**
```bash
sudo chmod 644 /etc/squid/auth/passwords
sudo chown squid:squid /etc/squid/auth/passwords
sudo systemctl restart squid
```

---

### Test Authentication

**Test Squid (HTTP):**
```bash
curl -x http://YOUR_IP:8888 --proxy-user USERNAME:PASSWORD https://ifconfig.me
```

**Test Dante (SOCKS5):**
```bash
curl --socks5 YOUR_IP:1080 --proxy-user USERNAME:PASSWORD https://ifconfig.me
```

Both should return your Oracle instance's IP.

---

## Problem 3: Slow Performance

### Symptoms
- Proxy works but very slow
- Pages take long to load
- Downloads are slow
- High latency

### Diagnosis

**Step 1: Check server load**
```bash
top
```

Press `q` to exit. Look at:
- CPU usage (should be low)
- Memory usage (should have free memory)
- Load average (should be < 1.0 for single core)

**If high load:**
- Too many concurrent connections
- Server under-resourced
- Consider upgrading Oracle instance

---

**Step 2: Check connection count**
```bash
sudo netstat -an | grep -E ":1080|:8888" | grep ESTABLISHED | wc -l
```

**If very high (>100):**
- Limit connections in config
- Upgrade server resources
- Someone may be abusing your proxy

---

**Step 3: Check disk space**
```bash
df -h
```

**If low on space:**
```bash
# Clean Squid cache
sudo systemctl stop squid
sudo rm -rf /var/spool/squid/*
sudo squid -z
sudo systemctl start squid

# Clean system logs
sudo journalctl --vacuum-time=7d
```

---

**Step 4: Test network latency**
```bash
# From your proxy server to internet
ping -c 5 8.8.8.8

# From your computer to proxy server
ping -c 5 YOUR_PROXY_IP
```

**High latency causes:**
- Geographic distance
- Oracle region far from you
- ISP routing issues

**Solutions:**
- Create Oracle instance in closer region
- Use different ISP/network
- Accept higher latency

---

**Step 5: Check Squid cache**
```bash
# View cache stats
sudo cat /var/log/squid/cache.log | grep -i "cache"

# Increase cache size
sudo nano /etc/squid/squid.conf

# Change this line (default 100MB):
cache_dir ufs /var/spool/squid 5000 16 256

# Rebuild cache
sudo systemctl stop squid
sudo rm -rf /var/spool/squid/*
sudo squid -z
sudo systemctl start squid
```

---

### Performance Optimization

**1. Optimize Squid**
```bash
sudo nano /etc/squid/squid.conf

# Add these lines:
max_filedesc 4096
dns_nameservers 8.8.8.8 1.1.1.1
read_timeout 5 minutes
request_timeout 5 minutes

# Restart
sudo systemctl restart squid
```

**2. Use different DNS**
```bash
# Test current DNS
dig @8.8.8.8 google.com +stats

# Change system DNS
sudo nano /etc/resolv.conf

# Add:
nameserver 1.1.1.1
nameserver 8.8.8.8
```

**3. Disable caching (if not needed)**
```bash
sudo nano /etc/squid/squid.conf

# Comment out cache_dir line:
# cache_dir ufs /var/spool/squid 100 16 256

# Add:
cache deny all

# Restart
sudo systemctl restart squid
```

---

## Problem 4: Intermittent Failures

### Symptoms
- Works sometimes, fails other times
- Connection drops after working
- Proxy works then stops responding
- Services keep restarting

### Diagnosis

**Step 1: Check service logs**
```bash
# Dante logs
sudo journalctl -u danted -n 50

# Squid logs
sudo tail -n 50 /var/log/squid/cache.log

# Look for errors, crashes, or restarts
```

**Common error messages:**
- "Out of memory" → Upgrade instance
- "Too many open files" → Increase limits
- "Permission denied" → Fix file permissions
- "Address already in use" → Port conflict

---

**Step 2: Check memory**
```bash
free -h
```

**If very low free memory:**
```bash
# Check what's using memory
ps aux --sort=-%mem | head -10

# Add swap space
sudo dd if=/dev/zero of=/swapfile bs=1M count=2048
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
```

---

**Step 3: Check for automatic restarts**
```bash
# Check if services are set to restart
systemctl show danted | grep Restart
systemctl show squid | grep Restart
```

**If restarting too often:**
```bash
# View restart count
systemctl status danted
systemctl status squid

# Check why it's restarting
journalctl -u danted --since "1 hour ago"
journalctl -u squid --since "1 hour ago"
```

---

**Step 4: Check for port conflicts**
```bash
# See what's using proxy ports
sudo lsof -i :1080
sudo lsof -i :8888
```

**If multiple processes:**
- Kill duplicate processes
- Check for misconfigurations
- Ensure only one proxy service per port

---

**Step 5: Check Oracle Cloud limits**

Oracle Free Tier has limits:
- 10TB/month bandwidth
- CPU throttling on always-free instances
- Network limits

**Check bandwidth usage:**
1. Oracle Cloud Console
2. Governance → Budgets
3. Cost Analysis → Usage

**If exceeding:**
- Reduce usage
- Upgrade to paid tier
- Wait for monthly reset

---

### Reliability Improvements

**1. Increase service limits**
```bash
# Increase file descriptors for Squid
sudo nano /etc/systemd/system/squid.service.d/override.conf

# Add:
[Service]
LimitNOFILE=8192

# Reload and restart
sudo systemctl daemon-reload
sudo systemctl restart squid
```

**2. Add monitoring**
```bash
# Create monitoring script
cat > /root/monitor-proxy.sh << 'EOF'
#!/bin/bash
# Check if services are running
systemctl is-active --quiet danted || systemctl restart danted
systemctl is-active --quiet squid || systemctl restart squid
EOF

chmod +x /root/monitor-proxy.sh

# Add to cron (check every 5 minutes)
echo "*/5 * * * * /root/monitor-proxy.sh" | sudo crontab -
```

**3. Enable persistent logging**
```bash
# Keep logs longer
sudo journalctl --vacuum-time=30d

# Rotate Squid logs
sudo nano /etc/logrotate.d/squid

# Add:
/var/log/squid/*.log {
    daily
    rotate 7
    compress
    missingok
    notifempty
}
```

---

## Problem 5: Specific Application Issues

### Web Browsers

**Firefox not connecting:**
1. Check if DNS proxy is enabled
2. Settings → Network → Connection Settings
3. Enable "Proxy DNS when using SOCKS v5"

**Chrome not working:**
1. Try using SOCKS5 instead of HTTP
2. Use extension "Proxy SwitchyOmega"
3. Configure authentication in extension

**Edge/Safari issues:**
1. These don't support SOCKS5 auth well
2. Use HTTP proxy instead
3. Or use Firefox/Chrome

---

### Programming Languages

**Python SSL errors:**
```python
# Disable SSL verification (for testing only)
import requests
proxies = {'http': 'socks5://user:pass@ip:1080'}
requests.get(url, proxies=proxies, verify=False)
```

**Node.js connection issues:**
```bash
# Set environment variables
export ALL_PROXY=socks5://user:pass@ip:1080
export NODE_TLS_REJECT_UNAUTHORIZED=0  # For testing only
```

**cURL timeout:**
```bash
# Increase timeout
curl --socks5 IP:1080 -U user:pass --max-time 60 URL
```

---

### Gaming / P2P

**Steam / Game clients:**
- Use SOCKS5 proxy in game settings
- Some games don't support authenticated proxies
- May need to allow unauthenticated local connections

**Torrents:**
1. qBittorrent/Transmission support SOCKS5
2. Configure in client settings
3. Test with: Tools → Options → Connection → Proxy
4. Enable "Use proxy for peer connections"

---

## Problem 6: Oracle Cloud Specific Issues

### Instance Suspended

**Check instance state:**
1. Oracle Cloud Console
2. Compute → Instances
3. Check state

**If stopped/terminated:**
- Free tier instances may be reclaimed
- Start instance manually
- Services should auto-start

---

### Network Issues After Reboot

**Fix:**
```bash
# Restore iptables rules
sudo iptables-restore < /etc/iptables/rules.v4

# Restart services
sudo systemctl restart danted squid

# Or run complete fix
sudo ./complete-fix.sh
```

---

### Bandwidth Limit Reached

**Symptoms:**
- Suddenly stopped working mid-month
- All connections fail

**Check:**
1. Oracle Cloud Console → Cost Management
2. Look for bandwidth overage

**Solution:**
- Wait for monthly reset
- Upgrade to paid tier
- Monitor usage more closely

---

## Advanced Diagnostics

### Full System Check

```bash
#!/bin/bash
echo "=== System Info ==="
uname -a
df -h
free -h

echo ""
echo "=== Proxy Services ==="
systemctl status danted --no-pager
systemctl status squid --no-pager

echo ""
echo "=== Network ==="
ip addr
ip route
curl -s ifconfig.me

echo ""
echo "=== Firewall ==="
iptables -L -n
firewall-cmd --list-all 2>/dev/null

echo ""
echo "=== Listening Ports ==="
netstat -tulpn | grep -E "1080|8888"

echo ""
echo "=== Active Connections ==="
netstat -an | grep -E ":1080|:8888" | grep ESTABLISHED

echo ""
echo "=== Logs ==="
journalctl -u danted -n 10 --no-pager
tail -n 10 /var/log/squid/access.log
```

Save as `full-diagnostics.sh` and run:
```bash
chmod +x full-diagnostics.sh
sudo ./full-diagnostics.sh > diagnostics.txt
```

---

### Packet Capture

If all else fails, capture network traffic:

```bash
# Install tcpdump
sudo dnf install -y tcpdump

# Capture on proxy ports
sudo tcpdump -i any -n port 1080 or port 8888 -w proxy-traffic.pcap

# Let it run while reproducing issue (Ctrl+C to stop)

# Download and analyze with Wireshark
```

---

## Getting More Help

### Before Asking for Help

1. **Run diagnostics:**
   ```bash
   sudo ./health-check.sh > health.txt
   ```

2. **Run auto-fix:**
   ```bash
   sudo ./complete-fix.sh > fix-output.txt
   ```

3. **Collect logs:**
   ```bash
   sudo journalctl -u danted -n 100 > danted.log
   sudo journalctl -u squid -n 100 > squid.log
   ```

4. **Test connectivity:**
   ```bash
   curl --socks5 YOUR_IP:1080 -U user:pass -v https://ifconfig.me 2>&1 | tee connection-test.txt
   ```

### Information to Include

When asking for help, provide:
- Oracle Cloud region
- Instance type (Always Free / Paid)
- Your client OS (Windows/Mac/Linux)
- Output from health-check.sh
- Relevant log snippets
- Exact error messages
- What you've already tried

---

## Prevention

### Regular Maintenance

**Daily:**
```bash
# Quick check
sudo systemctl status danted squid
```

**Weekly:**
```bash
# Full health check
sudo ./health-check.sh

# Check logs for errors
sudo journalctl -u danted --since "1 week ago" | grep -i error
sudo grep -i error /var/log/squid/cache.log
```

**Monthly:**
```bash
# Update system
sudo dnf update -y

# Restart services
sudo systemctl restart danted squid

# Clean logs
sudo journalctl --vacuum-time=30d

# Backup config
sudo tar -czf proxy-backup-$(date +%Y%m%d).tar.gz \
  /etc/danted.conf \
  /etc/squid/squid.conf \
  /etc/squid/auth/passwords \
  /etc/proxy-auth/credentials
```

---

**Remember:** 90% of issues are Oracle Cloud Security List configuration!  
Always double-check that first! 🎯
