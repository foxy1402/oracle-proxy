# Cloud Smart Proxy

Automated SOCKS5 and HTTP proxy setup for **Oracle Linux 8** and **Ubuntu 20.04/22.04/24.04** with optional web dashboard.

## 🚀 Quick Install

### Oracle Linux 8
```bash
git clone https://github.com/foxy1402/oracle-monitoring-dashboard.git
cd oracle-monitoring-dashboard
chmod +x *.sh
sudo ./oracle-proxy-setup.sh
```

### Ubuntu 20.04/22.04/24.04
```bash
git clone https://github.com/foxy1402/oracle-monitoring-dashboard.git
cd oracle-monitoring-dashboard
chmod +x *.sh
sudo ./ubuntu-proxy-setup.sh
```

## ⚠️ Important: Cloud Firewall Setup

**After installation**, add these inbound rules in your cloud console:

| Port | Protocol | Source | Description |
|------|----------|--------|-------------|
| **1080** | TCP | 0.0.0.0/0 | SOCKS5 Proxy |
| **8888** | TCP | 0.0.0.0/0 | HTTP Proxy |
| **1234** | TCP | 0.0.0.0/0 | Dashboard (optional) |

**Without these rules, your proxy won't work from outside!**

## ✅ What's Included

### Oracle Linux 8
- **SOCKS5**: Dante (port 1080) - PAM authentication
- **HTTP**: Squid (port 8888) - htpasswd authentication
- **Dashboard**: Python web interface (port 1234)
- **Security**: SELinux compatible

### Ubuntu
- **SOCKS5**: microsocks (port 1080) - built from source
- **HTTP**: Squid (port 8888) - htpasswd authentication
- **Dashboard**: Python web interface (port 1234)
- **Security**: AppArmor compatible

## 🧪 Test Connection

Replace `YOUR_IP`, `USER`, and `PASS` with your values:

### Test SOCKS5
```bash
curl --socks5 YOUR_IP:1080 --proxy-user USER:PASS https://ifconfig.me
```

### Test HTTP
```bash
curl -x http://YOUR_IP:8888 --proxy-user USER:PASS https://ifconfig.me
```

**Expected output:** Your server's public IP

## 🌐 Install Dashboard (Optional)

### Oracle Linux 8
```bash
sudo ./install-dashboard.sh
```

### Ubuntu
```bash
sudo ./ubuntu-install-dashboard.sh
```

Access at: `http://YOUR_IP:1234`

**Dashboard Features:**
- ✅ Real-time service monitoring
- ✅ Active connections viewer
- ✅ Add proxy users
- ✅ Block/unblock IPs
- ✅ Restart services
- ✅ Auto-fix issues

## 🛠️ Useful Commands

### Check Status

**Oracle Linux:**
```bash
sudo systemctl status danted    # SOCKS5
sudo systemctl status squid     # HTTP
```

**Ubuntu:**
```bash
sudo systemctl status microsocks  # SOCKS5
sudo systemctl status squid       # HTTP
```

### View Logs

**Oracle Linux:**
```bash
sudo journalctl -u danted -f       # SOCKS5 logs
sudo tail -f /var/log/squid/access.log  # HTTP logs
```

**Ubuntu:**
```bash
sudo journalctl -u microsocks -f   # SOCKS5 logs
sudo tail -f /var/log/squid/access.log  # HTTP logs
```

### Run Health Check

**Oracle Linux:**
```bash
sudo ./health-check.sh
```

**Ubuntu:**
```bash
sudo ./ubuntu-health-check.sh
```

### Auto-Fix Issues

**Oracle Linux:**
```bash
sudo ./complete-fix.sh
```

**Ubuntu:**
```bash
sudo ./ubuntu-complete-fix.sh
```

### Add More Users

```bash
# Via command line
sudo htpasswd -b /etc/squid/auth/passwords newuser newpass
sudo systemctl restart squid

# Or via dashboard at http://YOUR_IP:1234
```

## 🐛 Troubleshooting

### Can't Connect from Outside?

**90% of issues: Cloud firewall not configured**
- Check Security Lists/Security Groups in cloud console
- Verify ports 1080, 8888, 1234 are open to 0.0.0.0/0
- Double-check source CIDR is 0.0.0.0/0, not your current IP

**Check local firewall:**
```bash
sudo iptables -L INPUT -n | grep -E "1080|8888"
```

### Service Won't Start?

**Oracle Linux:**
```bash
sudo journalctl -u danted -n 50    # SOCKS5 errors
sudo journalctl -u squid -n 50     # HTTP errors
```

**Ubuntu:**
```bash
sudo journalctl -u microsocks -n 50  # SOCKS5 errors
sudo journalctl -u squid -n 50       # HTTP errors
```

**Try auto-fix:**
```bash
sudo ./complete-fix.sh          # Oracle Linux
sudo ./ubuntu-complete-fix.sh   # Ubuntu
```

### Authentication Failed?

**Check password file exists:**
```bash
cat /etc/squid/auth/passwords  # Should show username:hash
```

**Re-add user:**
```bash
sudo htpasswd -b /etc/squid/auth/passwords USERNAME PASSWORD
sudo systemctl restart squid
```

## 🔒 Security Notes

### Password Storage
- ✅ **SOCKS5**: Hashed (Oracle: shadow file, Ubuntu: credentials file)
- ✅ **HTTP**: htpasswd bcrypt hash
- ✅ **Dashboard**: PBKDF2-SHA256 (100k iterations)
- ✅ **No plain text** passwords stored anywhere

### Best Practices
- Use strong passwords (12+ characters)
- Monitor logs regularly
- Block abusive IPs via dashboard
- For production: Use SSH tunnel for dashboard
  ```bash
  ssh -L 1234:localhost:1234 user@server
  # Access: http://localhost:1234
  ```

## 📁 Configuration Files

### Oracle Linux
```
/etc/danted.conf                    # SOCKS5 config
/etc/squid/squid.conf               # HTTP config
/etc/squid/auth/passwords           # User passwords
/etc/proxy-configs/                 # Client guides
```

### Ubuntu
```
/etc/microsocks/credentials         # SOCKS5 credentials
/etc/squid/squid.conf               # HTTP config
/etc/squid/auth/passwords           # User passwords
/etc/proxy-configs/                 # Client guides
```

## 🎯 Use Cases

- ✅ Bypass geo-restrictions
- ✅ Secure public WiFi browsing
- ✅ Web scraping with rotating IPs
- ✅ Privacy protection
- ✅ Development/testing

## 📄 License

MIT License - Free to use and modify

## 🙏 Credits

- **Dante**: https://www.inet.no/dante/
- **microsocks**: https://github.com/rofl0r/microsocks
- **Squid**: http://www.squid-cache.org/

---

**Need help?** Run health check or check logs above.
