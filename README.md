# Oracle Cloud Smart Proxy - Complete Setup Package

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform: Oracle Linux 8](https://img.shields.io/badge/Platform-Oracle%20Linux%208-red.svg)](https://www.oracle.com/linux/)
[![Security: Hardened](https://img.shields.io/badge/Security-Hardened-green.svg)](SECURITY-FIXES.md)

> **🎯 Create SOCKS5 and HTTP proxy on Oracle Cloud with auto-configuration**  
> Handles Oracle Cloud's strict firewall rules automatically with enterprise-grade security

---

## ⚡ 30-Second Quick Start

```bash
# 1. On your Oracle instance
git clone https://github.com/foxy1402/oracle-proxy.git
cd oracle-proxy
chmod +x *.sh
sudo ./oracle-proxy-setup.sh

# 2. In Oracle Cloud Console
# Add Security Rules: TCP Port 1080 (SOCKS5) and 8888 (HTTP) from 0.0.0.0/0

# 3. Test your proxy
curl --socks5 YOUR_IP:1080 --proxy-user USERNAME:PASSWORD https://ifconfig.me

# Done!
```

---

## 🌟 Features

### Core Functionality
- ✅ **SOCKS5 Proxy** (Dante) - Port 1080
- ✅ **HTTP/HTTPS Proxy** (Squid) - Port 8888
- ✅ **Web Dashboard** - Port 1234
- ✅ **Authentication** - Username/password protection
- ✅ **Auto-Configuration** - One-command setup
- ✅ **Oracle Cloud Native** - Handles OCI networking quirks

### Security Features (v2.0)
- 🔒 **No Plain Text Passwords** - All credentials hashed (PBKDF2-SHA256)
- 🔒 **Input Validation** - Prevents injection attacks
- 🔒 **Non-Root Dashboard** - Runs as dedicated user
- 🔒 **SELinux Compatible** - Proper policies, not disabled
- 🔒 **Audit Logging** - Track all access
- 🔒 **Secure Credential Handling** - No shell exposure

### Management Features
- 📊 **Real-time Monitoring** - Active connections and stats
- 🔧 **Auto-Fix Script** - Automatically repair common issues
- 🏥 **Health Check** - Comprehensive diagnostics
- 👥 **User Management** - Add users via web or CLI
- 📱 **Mobile-Friendly** - Responsive dashboard design

### Automation
- ⚙️ **Auto-Start on Boot** - Services persist through reboots
- 🔄 **Service Recovery** - Automatic restart on failure
- 🛡️ **Firewall Persistence** - Rules survive reboots
- 📝 **Installation Verification** - Confirms everything works

---

## 📖 What This Does

Setting up a proxy on Oracle Cloud is challenging because:
- ❌ Oracle Cloud has strict firewall rules that block proxy ports by default
- ❌ Standard proxy guides don't account for Oracle Linux specifics
- ❌ Multiple services need to work together (dante, squid, iptables, firewalld)
- ❌ Authentication setup is complex

**This repository provides:**
- ✅ **Automated installation** - One command sets up everything
- ✅ **SOCKS5 + HTTP proxy** - Both protocols with authentication
- ✅ **Auto-fix script** - Automatically solves connection problems
- ✅ **Web dashboard** - Monitor and manage via browser
- ✅ **Oracle Cloud specific** - Handles OCI networking quirks

---

## 🔄 How It Works

```
Your Device                Oracle Cloud VM            Internet
    │                           │                        │
    │  1. SOCKS5/HTTP Request   │                        │
    │ ══════════════════════> │                        │
    │   (with authentication)    │                        │
    │                            │                        │
    │  2. Proxy forwards         │  3. Request sent      │
    │                            │ ═══════════════════> │
    │                            │   (as Oracle VM)       │
    │                            │                        │
    │  4. Response returns       │  5. Back to you       │
    │ <═══════════════════════════════════════════════ │
    │                            │                        │
   YOU                    YOUR PROXY SERVER          TARGET SITE
```

**The Challenge:** Oracle Cloud blocks all ports by default + complex authentication  
**The Solution:** This repository automates everything with smart scripts

---

## 🚀 Complete Installation Guide

### Prerequisites
- Oracle Cloud account with a Linux 8 ARM instance
- SSH access to your instance
- Basic Linux knowledge

### Step 1: Upload Scripts to Server

**Option A: Using Git (Recommended)**
```bash
# SSH into your Oracle instance
ssh opc@YOUR_INSTANCE_IP

# Install git and clone
sudo dnf install -y git
git clone https://github.com/foxy1402/oracle-proxy.git
cd oracle-proxy
```

**Option B: Manual Upload**
1. Download this repository as ZIP
2. Extract on your computer
3. Use WinSCP/FileZilla to upload to Oracle instance
4. SSH in and navigate to the folder

---

### Step 2: Run Installation Script

```bash
# Make scripts executable
chmod +x oracle-proxy-setup.sh complete-fix.sh install-dashboard.sh

# Run main installation (takes 3-5 minutes)
sudo ./oracle-proxy-setup.sh
```

**During installation, you'll be asked to:**
1. Set username for proxy authentication
2. Set password (minimum 8 characters)
3. Confirm Oracle Cloud Security List configuration

**What gets installed:**
- ✅ Dante SOCKS5 server (port 1080)
- ✅ Squid HTTP proxy (port 8888)
- ✅ Authentication system
- ✅ Firewall rules (iptables + firewalld)
- ✅ Auto-start on boot

---

### Step 3: Configure Oracle Cloud Security List

⚠️ **CRITICAL - Most connection failures happen here!**

Oracle Cloud blocks all ports by default. You MUST add firewall rules:

1. **Login** to [Oracle Cloud Console](https://cloud.oracle.com)

2. **Navigate** to networking:
   - Click hamburger menu (☰)
   - Click **Networking**
   - Click **Virtual Cloud Networks**

3. **Select your VCN:**
   - Click on your VCN name

4. **Go to Security Lists:**
   - Left sidebar → Click **Security Lists**
   - Click **Default Security List for vcn-...**

5. **Add Rule 1 (SOCKS5):**
   - Click blue **Add Ingress Rules** button
   - Fill in:
     - **Source CIDR:** `0.0.0.0/0`
     - **IP Protocol:** `TCP`
     - **Destination Port Range:** `1080`
     - **Description:** SOCKS5 Proxy
   - Click **Add Ingress Rules**

6. **Add Rule 2 (HTTP Proxy):**
   - Click **Add Ingress Rules** again
   - Fill in:
     - **Source CIDR:** `0.0.0.0/0`
     - **IP Protocol:** `TCP`
     - **Destination Port Range:** `8888`
     - **Description:** HTTP Proxy
   - Click **Add Ingress Rules**

✅ **Verification:** You should see both rules in the ingress rules list

---

### Step 4: Get Your Proxy Credentials

```bash
# View your configuration
sudo cat /etc/proxy-configs/quick-reference.txt
```

This shows:
- Your public IP address
- Proxy ports (1080 for SOCKS5, 8888 for HTTP)
- Username you created
- Password (stored securely)

---

### Step 5: Test Your Proxy

**From any computer with internet:**

```bash
# Test SOCKS5 proxy
curl --socks5 YOUR_IP:1080 --proxy-user USERNAME:PASSWORD https://ifconfig.me

# Test HTTP proxy
curl -x http://YOUR_IP:8888 --proxy-user USERNAME:PASSWORD https://ifconfig.me

# Expected output: YOUR_IP (your Oracle instance IP)
```

✅ **If you see your Oracle IP:** Your proxy is working!  
❌ **If you get errors:** Run the fix script (see Troubleshooting below)

---

## 🌐 OPTIONAL: Install Web Dashboard

**⚠️ Only install AFTER completing Steps 1-5 above!**

The web dashboard lets you:
- Monitor active connections in real-time
- View proxy statistics
- Add new users
- Run diagnostics
- Auto-fix issues

### Dashboard Installation

#### Step 1: Install Dashboard

```bash
chmod +x install-dashboard.sh
sudo ./install-dashboard.sh
```

Wait 1-2 minutes for installation.

---

#### Step 2: Add Oracle Cloud Firewall Rule

1. **Go back** to Oracle Cloud Console → Security Lists
2. **Add Ingress Rule:**
   - **Source CIDR:** `0.0.0.0/0`
   - **IP Protocol:** `TCP`
   - **Destination Port Range:** `1234`
   - **Description:** Proxy Dashboard

---

#### Step 3: Access Dashboard

```bash
# Get your server IP
curl ifconfig.me
```

Open in browser: `http://YOUR_IP:1234`

**First visit:**
- You'll see a "Set Password" screen
- Enter a strong password (8+ characters)
- This is for dashboard access only (separate from proxy auth)

**After setup:**
- Login with the password you created
- Dashboard refreshes every 30 seconds

---

## 📱 Using Your Proxy

### Windows Configuration

**Method 1: System Settings (HTTP Only)**
1. Settings → Network & Internet → Proxy
2. Manual proxy setup → ON
3. Proxy server: `YOUR_IP:8888`
4. Save

**Method 2: Browser (SOCKS5 Recommended)**

**Firefox:**
1. Settings → General → Network Settings
2. Manual proxy configuration
3. SOCKS Host: `YOUR_IP`
4. Port: `1080`
5. Select "SOCKS v5"
6. Check "Proxy DNS when using SOCKS v5"

**Chrome:**
- Use extension like "Proxy SwitchyOmega"
- Add SOCKS5 proxy: `YOUR_IP:1080`

---

### macOS Configuration

1. System Preferences → Network
2. Select your network → Advanced
3. Proxies tab
4. For SOCKS: Check "SOCKS Proxy"
   - Server: `YOUR_IP`
   - Port: `1080`
5. For HTTP: Check "Web Proxy" and "Secure Web Proxy"
   - Server: `YOUR_IP`
   - Port: `8888`

---

### Linux Configuration

**Environment Variables (SOCKS5):**
```bash
export ALL_PROXY=socks5://USERNAME:PASSWORD@YOUR_IP:1080
```

**Environment Variables (HTTP):**
```bash
export http_proxy=http://USERNAME:PASSWORD@YOUR_IP:8888
export https_proxy=http://USERNAME:PASSWORD@YOUR_IP:8888
```

**Make permanent:**
```bash
# Add to ~/.bashrc or ~/.zshrc
echo 'export ALL_PROXY=socks5://USERNAME:PASSWORD@YOUR_IP:1080' >> ~/.bashrc
source ~/.bashrc
```

---

### Programming Examples

**Python:**
```python
import requests

# Using SOCKS5
proxies = {
    'http': 'socks5://USERNAME:PASSWORD@YOUR_IP:1080',
    'https': 'socks5://USERNAME:PASSWORD@YOUR_IP:1080'
}

# Using HTTP
proxies = {
    'http': 'http://USERNAME:PASSWORD@YOUR_IP:8888',
    'https': 'http://USERNAME:PASSWORD@YOUR_IP:8888'
}

response = requests.get('https://ifconfig.me', proxies=proxies)
print(response.text)  # Should show YOUR_IP
```

**Node.js:**
```javascript
const SocksProxyAgent = require('socks-proxy-agent');
const fetch = require('node-fetch');

const agent = new SocksProxyAgent('socks5://USERNAME:PASSWORD@YOUR_IP:1080');

fetch('https://ifconfig.me', { agent })
  .then(res => res.text())
  .then(body => console.log(body));
```

**cURL:**
```bash
# SOCKS5
curl --socks5 YOUR_IP:1080 --proxy-user USERNAME:PASSWORD https://ifconfig.me

# HTTP
curl -x http://YOUR_IP:8888 --proxy-user USERNAME:PASSWORD https://ifconfig.me
```

---

## 🔧 Troubleshooting

### Problem 1: Connection Refused

**Symptoms:** Can't connect to proxy at all

**Causes:**
1. Oracle Cloud Security List not configured (90% of cases)
2. Proxy services not running
3. Firewall blocking ports

**Solution:**

```bash
# Run auto-fix
sudo ./complete-fix.sh

# Check if services are running
sudo systemctl status danted    # SOCKS5
sudo systemctl status squid     # HTTP

# Check if ports are open
sudo netstat -tulpn | grep -E "1080|8888"

# Verify firewall rules
sudo iptables -L INPUT -n | grep -E "1080|8888"
```

**If still fails:** Double-check Oracle Cloud Security List (Step 3 above)

---

### Problem 2: Authentication Failed

**Symptoms:** Connection works but rejected with "407 Proxy Authentication Required"

**Causes:**
- Wrong username/password
- User not added to all required systems

**Solution:**

```bash
# View your credentials
sudo cat /etc/proxy-auth/credentials

# Re-add user
sudo htpasswd -b /etc/squid/auth/passwords USERNAME PASSWORD
echo "USERNAME:PASSWORD" | sudo chpasswd

# Restart services
sudo systemctl restart danted
sudo systemctl restart squid
```

---

### Problem 3: Slow Speeds

**Causes:**
- High latency to Oracle region
- Server overloaded
- ISP throttling proxy ports

**Solution:**

```bash
# Check server load
top

# Check connection count
sudo netstat -an | grep -E ":1080|:8888" | grep ESTABLISHED | wc -l

# Check Oracle instance resources
df -h
free -h
```

**Consider:**
- Upgrading to larger Oracle instance
- Choosing Oracle region closer to you
- Using different ports (see Advanced Configuration)

---

### Problem 4: Proxy Works Then Stops

**Symptoms:** Works for a while then stops responding

**Causes:**
- Services crashed
- Out of memory
- Firewall rules lost after reboot

**Solution:**

```bash
# Check service logs
sudo journalctl -u danted -f
sudo tail -f /var/log/squid/access.log

# Restart services
sudo systemctl restart danted
sudo systemctl restart squid

# Re-apply firewall rules
sudo ./complete-fix.sh
```

---

### Run Full Diagnostics

```bash
# Comprehensive check
sudo ./oracle-proxy-setup.sh --diagnose

# View all configuration
sudo cat /etc/proxy-configs/quick-reference.txt

# Test connectivity
curl --socks5 YOUR_IP:1080 --proxy-user USERNAME:PASSWORD https://ifconfig.me
```

---

## 🛡️ Security Best Practices

### 1. Use Strong Authentication

```bash
# Change password regularly
sudo htpasswd -b /etc/squid/auth/passwords USERNAME NEW_PASSWORD
echo "USERNAME:NEW_PASSWORD" | sudo chpasswd
sudo systemctl restart danted squid
```

### 2. Limit Access by IP (Recommended)

**In Oracle Cloud Security List:**
- Instead of `0.0.0.0/0`, use `YOUR_HOME_IP/32`
- Find your IP: https://whatismyip.com

**In dante config:**
```bash
sudo nano /etc/danted.conf

# Change this line:
client pass {
    from: YOUR_HOME_IP/32 to: 0.0.0.0/0
    # ...
}

sudo systemctl restart danted
```

### 3. Monitor Access

```bash
# View active connections
sudo netstat -an | grep -E ":1080|:8888" | grep ESTABLISHED

# View HTTP proxy logs
sudo tail -f /var/log/squid/access.log

# View SOCKS5 logs
sudo journalctl -u danted -f
```

### 4. Use Non-Standard Ports (Advanced)

Change from default ports to avoid port scanning:

```bash
# Edit configurations
sudo nano /etc/danted.conf
# Change: internal: 0.0.0.0 port = 1080
# To:     internal: 0.0.0.0 port = 45678

sudo nano /etc/squid/squid.conf
# Change: http_port 8888
# To:     http_port 54321

# Update firewall
sudo iptables -I INPUT -p tcp --dport 45678 -j ACCEPT
sudo iptables -I INPUT -p tcp --dport 54321 -j ACCEPT

# Restart
sudo systemctl restart danted squid
```

**Don't forget:** Update Oracle Cloud Security List with new ports!

### 5. Add Additional Users

**Via Dashboard:**
- Login to dashboard
- "Add Proxy User" section
- Enter username and password

**Via Command Line:**
```bash
# Add new user
sudo htpasswd -b /etc/squid/auth/passwords newuser newpassword
sudo useradd -r -s /bin/false newuser
echo "newuser:newpassword" | sudo chpasswd

# Restart services
sudo systemctl restart danted squid
```

### 6. Keep System Updated

```bash
# Update regularly
sudo dnf update -y

# Update specific packages
sudo dnf update squid dante-server iptables
```

---

## 📊 Performance Optimization

### Increase Connection Limits

**For Squid:**
```bash
sudo nano /etc/squid/squid.conf

# Add these lines:
max_filedesc 4096
dns_nameservers 8.8.8.8 1.1.1.1
dns_timeout 30 seconds

sudo systemctl restart squid
```

**For Dante:**
```bash
sudo nano /etc/danted.conf

# Increase client limit
client pass {
    from: 0.0.0.0/0 to: 0.0.0.0/0
    log: connect disconnect error
    maxconnections: 1000
}
```

### Enable Squid Caching (Speed up repeated requests)

```bash
sudo nano /etc/squid/squid.conf

# Change cache_dir size (default 100MB)
cache_dir ufs /var/spool/squid 5000 16 256

# Initialize new cache
sudo systemctl stop squid
sudo rm -rf /var/spool/squid/*
sudo squid -z
sudo systemctl start squid
```

---

## 📁 File Locations Reference

```
/etc/danted.conf                    # SOCKS5 server config
/etc/squid/squid.conf              # HTTP proxy config
/etc/squid/auth/passwords          # Proxy user credentials
/etc/proxy-auth/credentials        # Saved installation credentials
/etc/proxy-configs/                # Client configuration guides
  ├── quick-reference.txt          # Quick reference card
  ├── socks5-config.txt           # SOCKS5 setup guide
  └── http-proxy-config.txt       # HTTP proxy setup guide
/var/log/squid/access.log          # HTTP proxy access logs
/var/spool/squid/                  # Squid cache directory
/opt/proxy-dashboard/              # Dashboard files (if installed)
```

---

## 🎓 Understanding the Setup

### Why SOCKS5 AND HTTP?

- **SOCKS5:** Lower level, faster, supports any protocol (HTTP, FTP, SSH, etc.)
- **HTTP:** Better compatibility with some applications, easier to configure

Use SOCKS5 when possible for best performance.

### Why Authentication?

- Prevents unauthorized use of your proxy
- Protects your Oracle instance from abuse
- Helps track usage

### Why Two Services (Dante + Squid)?

- **Dante:** Best SOCKS5 implementation
- **Squid:** Industry-standard HTTP proxy with caching

They work together to provide both protocols.

### Why Oracle Cloud Security List?

Oracle Cloud has TWO firewall layers:
1. **Instance firewall** (iptables/firewalld) - Configured by script
2. **Network firewall** (Security List) - Must configure manually

Both must allow traffic for proxy to work.

---

## 📞 Getting Help

### Self-Help Resources

1. **Run diagnostics:**
   ```bash
   sudo ./oracle-proxy-setup.sh --diagnose
   ```

2. **Run auto-fix:**
   ```bash
   sudo ./complete-fix.sh
   ```

3. **Check logs:**
   ```bash
   sudo journalctl -u danted -n 50
   sudo tail -f /var/log/squid/access.log
   ```

4. **Test connectivity:**
   ```bash
   curl --socks5 YOUR_IP:1080 --proxy-user USER:PASS https://ifconfig.me
   ```

### Common Questions

**Q: Can I use this for torrenting?**  
A: Yes, SOCKS5 supports P2P traffic. Configure your torrent client to use SOCKS5 proxy.

**Q: Does this work with Oracle Free Tier?**  
A: Yes! Designed and tested on Oracle Cloud Free Tier ARM instances.

**Q: Can multiple devices use the proxy simultaneously?**  
A: Yes! Unlimited concurrent connections (within Oracle instance resources).

**Q: Will this work on other clouds (AWS, GCP)?**  
A: The scripts are Oracle-specific, but concepts apply. You'd need to modify firewall configuration parts.

**Q: How much bandwidth can I use?**  
A: Oracle Free Tier includes 10TB/month outbound. Monitor usage in Oracle Console.

**Q: Can I make money selling proxy access?**  
A: Check Oracle's Terms of Service. Generally, commercial use requires paid account.

---

## 🔄 Maintenance

### Daily
- Check dashboard for unusual activity
- Monitor active connections

### Weekly
```bash
# Check disk space
df -h

# Review logs
sudo journalctl -u danted --since "1 week ago" | grep -i error
sudo grep -i error /var/log/squid/cache.log
```

### Monthly
```bash
# Update system
sudo dnf update -y

# Restart services
sudo systemctl restart danted squid

# Clean squid cache
sudo systemctl stop squid
sudo rm -rf /var/spool/squid/*
sudo squid -z
sudo systemctl start squid

# Rotate logs
sudo logrotate -f /etc/logrotate.d/squid
```

### Backup Configuration
```bash
# Backup all configs
sudo tar -czf proxy-backup-$(date +%Y%m%d).tar.gz \
  /etc/danted.conf \
  /etc/squid/squid.conf \
  /etc/squid/auth/passwords \
  /etc/proxy-auth/credentials

# Download backup to your computer
scp opc@YOUR_IP:~/proxy-backup-*.tar.gz ./
```

---

## 📝 Quick Command Reference

```bash
# Service management
sudo systemctl start danted          # Start SOCKS5
sudo systemctl stop danted           # Stop SOCKS5
sudo systemctl restart danted        # Restart SOCKS5
sudo systemctl status danted         # Check SOCKS5 status

sudo systemctl start squid           # Start HTTP
sudo systemctl stop squid            # Stop HTTP
sudo systemctl restart squid         # Restart HTTP
sudo systemctl status squid          # Check HTTP status

# Diagnostics
sudo ./oracle-proxy-setup.sh --diagnose
sudo ./complete-fix.sh
sudo netstat -tulpn | grep -E "1080|8888"

# View configs
sudo cat /etc/proxy-configs/quick-reference.txt
sudo cat /etc/danted.conf
sudo cat /etc/squid/squid.conf

# Logs
sudo journalctl -u danted -f
sudo tail -f /var/log/squid/access.log

# Add user
sudo htpasswd -b /etc/squid/auth/passwords USERNAME PASSWORD
sudo useradd -r -s /bin/false USERNAME
echo "USERNAME:PASSWORD" | sudo chpasswd
sudo systemctl restart danted squid

# Test proxy
curl --socks5 YOUR_IP:1080 --proxy-user USER:PASS https://ifconfig.me
curl -x http://YOUR_IP:8888 --proxy-user USER:PASS https://ifconfig.me
```

---

## 🎉 Success Checklist

- [ ] Scripts executed without errors
- [ ] Oracle Cloud Security List configured (TCP 1080 and 8888)
- [ ] Services running (`systemctl status danted squid`)
- [ ] Can connect with SOCKS5 client
- [ ] Can connect with HTTP proxy
- [ ] Authentication working
- [ ] IP shows Oracle instance IP when testing
- [ ] (Optional) Dashboard accessible and working

---

## 🔗 Additional Resources

- Oracle Cloud Networking Guide: https://docs.oracle.com/en-us/iaas/Content/Network/Concepts/overview.htm
- Dante Documentation: https://www.inet.no/dante/doc/
- Squid Documentation: http://www.squid-cache.org/Doc/
- SOCKS5 Protocol: https://tools.ietf.org/html/rfc1928

---

## 📊 Project Information

### Repository
- **GitHub:** [foxy1402/oracle-proxy](https://github.com/foxy1402/oracle-proxy)
- **Issues:** [Report a bug](https://github.com/foxy1402/oracle-proxy/issues)
- **Documentation:** Complete guides included
- **License:** MIT

### Version History
- **v2.0** (2026-01-30) - Security hardening, dashboard port 1234, production-ready
  - Removed plain text password storage
  - Added input validation
  - Dashboard runs as non-root
  - SELinux compatibility
  - See [SECURITY-FIXES.md](SECURITY-FIXES.md) for details
- **v1.0** - Initial release

### Requirements
- Oracle Cloud account (Free Tier supported)
- Oracle Linux 8 ARM instance
- SSH access
- Basic Linux knowledge

### Tested On
- ✅ Oracle Linux 8 (aarch64)
- ✅ Oracle Cloud Free Tier (Ampere A1)
- ✅ Oracle Cloud Always Free instances

### Support
- 📖 Read [README.md](README.md) for full documentation
- 🚀 Read [QUICK-START.md](QUICK-START.md) for beginners
- 🔧 Read [TROUBLESHOOTING.md](TROUBLESHOOTING.md) for fixes
- 🔒 Read [SECURITY-FIXES.md](SECURITY-FIXES.md) for security details
- 📊 Read [PROJECT-OVERVIEW.md](PROJECT-OVERVIEW.md) for architecture

### Contributing
Contributions welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Test your changes on Oracle Linux 8
4. Submit a pull request

### Security
- Security issues? Please report privately via GitHub Issues
- See [SECURITY-FIXES.md](SECURITY-FIXES.md) for security features
- Regular security updates recommended

---

## ⭐ Star This Repository

If this project helped you set up your Oracle Cloud proxy, please star it! ⭐

---

**Made with ❤️ for Oracle Cloud users struggling with proxy setup!**

**Happy proxying! 🚀**

---

## 📄 License

MIT License - See LICENSE file for details

Copyright (c) 2026 foxy1402

---

## 🔗 Quick Links

- [Installation Guide](README.md#-complete-installation-guide)
- [Quick Start](QUICK-START.md)
- [Troubleshooting](TROUBLESHOOTING.md)
- [Security Details](SECURITY-FIXES.md)
- [Dashboard Setup](README.md#-optional-install-web-dashboard)
- [GitHub Repository](https://github.com/foxy1402/oracle-proxy)

