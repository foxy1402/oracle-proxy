# Oracle Cloud Proxy - Quick Start Guide
**For Complete Beginners - Step by Step**

## 📋 Before You Start

You need:
- [ ] Oracle Cloud account
- [ ] Oracle Linux 8 instance created (Free Tier is fine)
- [ ] SSH access to your instance
- [ ] Instance's public IP address

---

## Part 1: Server Setup (On Oracle Instance)

**⏱️ Time: 5-7 minutes**

### Step 1.1: Connect to Your Server

```bash
ssh opc@YOUR_INSTANCE_IP
```

Replace `YOUR_INSTANCE_IP` with your actual IP.

---

### Step 1.2: Download Setup Scripts

```bash
# Install git
sudo dnf install -y git

# Download scripts
git clone https://github.com/foxy1402/oracle-proxy.git

# Enter directory
cd oracle-proxy
```

✅ **Checkpoint:** You should see files listed when you run `ls`

---

### Step 1.3: Make Scripts Executable

```bash
chmod +x oracle-proxy-setup.sh complete-fix.sh install-dashboard.sh
```

---

### Step 1.4: Run Installation

```bash
sudo ./oracle-proxy-setup.sh
```

**What happens:**
1. Installs proxy software (2-3 minutes)
2. Asks you to create username
3. Asks you to create password (8+ characters)
4. Asks you to confirm password
5. Configures everything automatically
6. Shows you configuration info

✅ **Write down:**
- Your username
- Your password
- The file paths shown

**⚠️ IMPORTANT:** When script says "Press ENTER when you have configured Oracle Cloud Security List", DON'T press enter yet! Continue to Part 2 first.

---

## Part 2: Oracle Cloud Firewall (In Web Browser)

**⏱️ Time: 3-4 minutes**

⚠️ **CRITICAL STEP - Don't Skip!**

### Step 2.1: Login to Oracle Cloud

Open https://cloud.oracle.com in your browser and login.

---

### Step 2.2: Navigate to Networking

1. Click the **☰ hamburger menu** (top left corner)
2. Click **Networking**
3. Click **Virtual Cloud Networks**

---

### Step 2.3: Select Your Network

1. Click on your **VCN name** (probably starts with "vcn-")
2. Look for it in the list under "Virtual Cloud Networks"

---

### Step 2.4: Go to Security Lists

1. On the **left sidebar**, click **"Security Lists"**
2. Click **"Default Security List for vcn-..."**

---

### Step 2.5: Add SOCKS5 Rule

1. Click the blue **"Add Ingress Rules"** button

2. Fill in the form **exactly** like this:

   ```
   Source Type:         CIDR
   Source CIDR:         0.0.0.0/0
   IP Protocol:         TCP
   Source Port Range:   (leave empty)
   Destination Port:    1080
   Description:         SOCKS5 Proxy
   ```

3. Click **"Add Ingress Rules"** at the bottom

✅ **Checkpoint:** You should see the new rule appear in the list

---

### Step 2.6: Add HTTP Proxy Rule

1. Click **"Add Ingress Rules"** button again

2. Fill in the form:

   ```
   Source Type:         CIDR
   Source CIDR:         0.0.0.0/0
   IP Protocol:         TCP
   Source Port Range:   (leave empty)
   Destination Port:    8888
   Description:         HTTP Proxy
   ```

3. Click **"Add Ingress Rules"**

✅ **Checkpoint:** You should now see TWO new rules (1080 and 8888)

---

### Step 2.7: Go Back to SSH Terminal

Now press **ENTER** in your SSH session to continue the installation.

---

## Part 3: Test Your Proxy

**⏱️ Time: 2 minutes**

### Step 3.1: Get Your Configuration Info

In the SSH terminal, you should see something like:

```
Server IP:    123.45.67.89
Username:     myuser
SOCKS5 Port:  1080
HTTP Port:    8888
```

✅ **Write this down!**

---

### Step 3.2: Test From Your Computer

**On Windows (PowerShell or Command Prompt):**

```powershell
# Test SOCKS5
curl --socks5 YOUR_IP:1080 --proxy-user USERNAME:PASSWORD https://ifconfig.me

# Test HTTP
curl -x http://YOUR_IP:8888 --proxy-user USERNAME:PASSWORD https://ifconfig.me
```

Replace:
- `YOUR_IP` with your server IP
- `USERNAME` with your username
- `PASSWORD` with your password

**Expected Result:** You should see your Oracle instance IP printed

✅ **If it works:** Congratulations! Your proxy is running!

❌ **If it fails:** Continue to Part 4

---

## Part 4: Troubleshooting (If Needed)

### Test 1: Are Services Running?

```bash
# Check SOCKS5
sudo systemctl status danted

# Check HTTP
sudo systemctl status squid
```

**Should say:** "active (running)" in green

**If not running:**
```bash
sudo systemctl restart danted
sudo systemctl restart squid
```

---

### Test 2: Are Ports Open?

```bash
sudo netstat -tulpn | grep -E "1080|8888"
```

**Should show:** Lines with `:1080` and `:8888`

**If nothing shows:**
```bash
sudo ./complete-fix.sh
```

---

### Test 3: Did You Configure Oracle Cloud?

Go back to Part 2 and verify:
- Both rules are present (1080 and 8888)
- Source CIDR is `0.0.0.0/0`
- IP Protocol is TCP
- Rules are not disabled

---

## Part 5: Using Your Proxy

### Windows - Firefox (Recommended for Beginners)

1. Open **Firefox**
2. Settings → **General** → scroll down to **Network Settings**
3. Click **Settings** button
4. Select **Manual proxy configuration**
5. Fill in:
   - **SOCKS Host:** Your server IP
   - **Port:** 1080
   - Select **SOCKS v5**
   - ✅ Check **"Proxy DNS when using SOCKS v5"**
6. Click **OK**

**Test:** Visit https://ifconfig.me in Firefox - should show your server IP

---

### Windows - Chrome

1. Install extension **"Proxy SwitchyOmega"**
2. Create new profile:
   - Protocol: SOCKS5
   - Server: Your IP
   - Port: 1080
3. Apply profile

---

### macOS

1. **System Preferences** → **Network**
2. Select your network → **Advanced**
3. **Proxies** tab
4. Check **SOCKS Proxy**
5. SOCKS Proxy Server: `YOUR_IP:1080`
6. Click **OK** → **Apply**

---

### Linux

```bash
# Add to ~/.bashrc
export ALL_PROXY=socks5://USERNAME:PASSWORD@YOUR_IP:1080

# Apply
source ~/.bashrc

# Test
curl https://ifconfig.me
```

---

## Part 6: (Optional) Install Dashboard

**Only do this AFTER Parts 1-5 work!**

### Step 6.1: Install

```bash
sudo ./install-dashboard.sh
```

Wait 1-2 minutes.

---

### Step 6.2: Add Firewall Rule

In Oracle Cloud Console (same place as Part 2):

1. **Add Ingress Rules**
2. Fill in:
   ```
   Source CIDR:    0.0.0.0/0
   IP Protocol:    TCP
   Destination:    8080
   Description:    Proxy Dashboard
   ```

---

### Step 6.3: Access Dashboard

1. Open browser
2. Go to: `http://YOUR_IP:1234`
3. First visit: Set a password (this is for dashboard only)
4. Login with that password

**Features:**
- ✅ See active connections
- ✅ View statistics
- ✅ Add new users
- ✅ Run diagnostics
- ✅ Auto-fix issues

---

## 🎉 Success Checklist

Your proxy is working if ALL are true:

- [ ] SOCKS5 service running (`systemctl status danted`)
- [ ] HTTP service running (`systemctl status squid`)
- [ ] Oracle Cloud rules added (1080, 8888)
- [ ] Test command shows your server IP
- [ ] Can browse internet through proxy

---

## 📞 Common Problems & Quick Fixes

### "Connection refused"

**Fix:**
```bash
sudo ./complete-fix.sh
```

Then retest.

---

### "Authentication failed"

**Check credentials:**
```bash
sudo cat /etc/proxy-auth/credentials
```

Make sure you're using the correct username and password.

---

### "Timeout" or "No response"

**99% of the time:** Oracle Cloud Security List not configured

Go back to Part 2 and verify both rules exist.

---

### Still not working?

**Run diagnostics:**
```bash
sudo ./oracle-proxy-setup.sh --diagnose
```

This will show exactly what's wrong.

---

## 📝 Important Commands

```bash
# Restart everything
sudo systemctl restart danted squid

# View logs
sudo journalctl -u danted -f
sudo tail -f /var/log/squid/access.log

# Run fix script
sudo ./complete-fix.sh

# View configuration
sudo cat /etc/proxy-configs/quick-reference.txt

# Add new user (via dashboard is easier)
sudo htpasswd -b /etc/squid/auth/passwords newuser newpass
```

---

## 🔒 Security Tips

1. **Change your password regularly**
2. **Use different passwords for:**
   - SSH login
   - Proxy authentication
   - Dashboard login
3. **Monitor the dashboard** for suspicious activity
4. **Don't share your credentials**

---

## 💡 Pro Tips

- **Use SOCKS5** when possible (faster than HTTP)
- **Dashboard auto-refreshes** every 30 seconds
- **Free Tier includes 10TB/month** bandwidth
- **Test with:** `curl --socks5 IP:1080 -U user:pass https://ifconfig.me`

---

## Next Steps

✅ **Setup complete!** You now have:
- Working SOCKS5 proxy on port 1080
- Working HTTP proxy on port 8888
- (Optional) Web dashboard on port 8080

**Recommended:**
1. Bookmark the dashboard URL
2. Save your credentials in a password manager
3. Test with different apps/browsers
4. Read the full README.md for advanced features

---

**Total Setup Time:** 15-20 minutes  
**Difficulty:** Beginner-friendly with this guide

**Questions?** Check the full README.md or run diagnostics!

**Happy proxying! 🚀**
