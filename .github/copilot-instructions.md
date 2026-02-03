# Oracle Cloud Smart Proxy - Copilot Instructions

## Project Overview

This project provides automated SOCKS5 and HTTP proxy setup for Oracle Cloud Linux 8 instances. The key challenge is navigating Oracle Cloud's strict two-layer firewall system (instance + Security List) and ensuring secure configuration.

**Target Environment:** Oracle Linux 8 (ARM/aarch64), specifically Oracle Cloud Always Free Tier

## Architecture

### Core Components
- **Dante** (SOCKS5 proxy) - Port 1080, PAM authentication
- **Squid** (HTTP proxy) - Port 8888, htpasswd authentication  
- **Web Dashboard** (optional) - Port 1234, Python native HTTP server, runs as `proxy-dashboard` user

### Two-Layer Firewall System
1. **Instance firewall** - iptables/firewalld (automated by scripts)
2. **Oracle Cloud Security List** - Must be configured manually by user in Oracle Console

This dual-layer architecture is the #1 source of connection failures and must be clearly documented.

### Authentication Flow
```
User Request → Security List Check → iptables/firewalld → Proxy Service → Auth (PAM/htpasswd) → Forward to Internet
```

## Key File Structure

### Installation Scripts (Bash)
- `oracle-proxy-setup.sh` - Main installer, creates all configs and services
- `complete-fix.sh` - Auto-repairs common issues (firewall rules, services, configs)
- `install-dashboard.sh` - Optional web dashboard installer
- `health-check.sh` - Comprehensive diagnostics

### Generated Configuration Files (after install)
- `/etc/danted.conf` - SOCKS5 server config
- `/etc/squid/squid.conf` - HTTP proxy config
- `/etc/squid/auth/passwords` - Hashed user credentials (htpasswd format)
- `/etc/proxy-auth/credentials` - Username only (NO password after v2.0)
- `/etc/proxy-configs/` - Client setup guides
- `/opt/proxy-dashboard/app.py` - Dashboard application

## Coding Conventions

### Bash Scripts

**Security-Critical Practices:**
```bash
# ALWAYS validate user input
validate_username() {
    local username="$1"
    if [[ ! "$username" =~ ^[a-zA-Z0-9_]{3,32}$ ]]; then
        log_error "Invalid username"
        return 1
    fi
    # Block reserved names
    local reserved="root daemon bin sys sync games man lp mail news uucp proxy nobody squid danted"
    if [[ " $reserved " =~ " $username " ]]; then
        log_error "Reserved username"
        return 1
    fi
}

# ALWAYS use stdin for passwords (never command line args)
echo "$username:$password" | chpasswd  # Good
chpasswd <<< "$username:$password"     # Also good
echo "$username:$password" | sudo chpasswd  # Avoid - visible in ps aux

# ALWAYS quote variables
rm -rf "$CACHE_DIR"/*  # Good
rm -rf $CACHE_DIR/*    # Bad - word splitting issues
```

**Logging Pattern:**
```bash
# Use color-coded logging functions
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
```

**Error Handling:**
```bash
# Don't hide errors silently
squid -z || log_warning "Squid cache initialization failed"  # Good
squid -z 2>/dev/null || true  # Bad - hides issues

# Verify critical operations
systemctl enable danted || log_warning "Failed to enable danted service"
```

### Python Dashboard

**Security Requirements:**
```python
# ALWAYS run as non-root user (proxy-dashboard)
# User created in install-dashboard.sh

# ALWAYS validate inputs
def validate_username(username):
    if not re.match(r'^[a-zA-Z0-9_]{3,32}$', username):
        return False
    reserved = {'root', 'daemon', 'squid', 'danted', 'nobody'}
    return username not in reserved

# ALWAYS use stdin for sensitive commands
process = subprocess.Popen(['chpasswd'], stdin=subprocess.PIPE)
process.communicate(f'{username}:{password}\n'.encode())
# NOT: subprocess.run(['bash', '-c', f'echo "{username}:{password}" | chpasswd'])

# Password hashing - use PBKDF2-SHA256 with 100k iterations
from hashlib import pbkdf2_hmac
import secrets
salt = secrets.token_bytes(32)
hash = pbkdf2_hmac('sha256', password.encode(), salt, 100000)
```

**SystemD Service Hardening:**
```ini
[Service]
User=proxy-dashboard
Group=proxy-dashboard
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/etc/squid/auth
```

## Build/Test/Lint Commands

**No automated build system** - these are deployment scripts, not compiled software.

### Testing on Oracle Linux 8

```bash
# Full installation test (clean instance)
sudo ./oracle-proxy-setup.sh

# Verify services running
sudo systemctl status danted
sudo systemctl status squid
sudo systemctl status proxy-dashboard  # If dashboard installed

# Test SOCKS5 connectivity
curl --socks5 localhost:1080 --proxy-user USERNAME:PASSWORD https://ifconfig.me

# Test HTTP proxy
curl -x http://localhost:8888 --proxy-user USERNAME:PASSWORD https://ifconfig.me

# Verify firewall rules
sudo iptables -L INPUT -n | grep -E "1080|8888|1234"

# Check ports listening
sudo netstat -tulpn | grep -E "1080|8888|1234"

# Run diagnostics
sudo ./health-check.sh

# Test auto-fix
sudo ./complete-fix.sh
```

### Manual Testing Checklist

- [ ] Fresh Oracle Linux 8 instance
- [ ] Run oracle-proxy-setup.sh with valid username/password
- [ ] Configure Oracle Cloud Security List (ports 1080, 8888, 1234)
- [ ] Test SOCKS5 proxy from external client
- [ ] Test HTTP proxy from external client
- [ ] Test dashboard access (if installed)
- [ ] Verify reboot persistence (services, firewall rules)
- [ ] Test complete-fix.sh recovery
- [ ] Test invalid input handling (username, password validation)

## Common Pitfalls

### Security Issues to Avoid

1. **Never store passwords in plain text**
   - Before v2.0: passwords stored in `/etc/proxy-auth/credentials` (FIXED)
   - Now: only hashed in `/etc/squid/auth/passwords` and system shadow file

2. **Never pass passwords via command line arguments**
   - Visible in `ps aux` output
   - Always use stdin: `echo "user:pass" | chpasswd`

3. **Always validate user input**
   - Username: `^[a-zA-Z0-9_]{3,32}$`
   - Password: 8-128 characters minimum
   - Block reserved names (root, daemon, squid, etc.)

4. **Never run web-facing services as root**
   - Dashboard runs as `proxy-dashboard` user
   - Uses sudo whitelist in `/etc/sudoers.d/proxy-dashboard`

### Oracle Cloud Specifics

**Security List Configuration is MANDATORY**
- 90% of "proxy not working" issues are missing Security List rules
- Must configure in Oracle Console (cannot be automated via scripts)
- Required ports: 1080 (SOCKS5), 8888 (HTTP), 1234 (Dashboard)
- Documentation must emphasize this step

**SELinux Compatibility**
```bash
# Don't globally disable SELinux
# Create proper policies instead:
semanage port -a -t http_cache_port_t -p tcp 8888
semanage port -a -t socks_port_t -p tcp 1080

# Only fall back to permissive if semanage unavailable
```

**Firewall Persistence**
```bash
# Both iptables and firewalld may be present
# Handle both, don't assume one or the other
# Use systemd service for iptables persistence:
cat > /etc/systemd/system/iptables-restore.service
```

### Common Bugs

**Dante Configuration**
- Must use correct IP address for `internal:` directive
- Must match PAM authentication with system users
- Log files must be writable

**Squid Configuration**  
- Must initialize cache: `squid -z`
- htpasswd file must exist before restart
- Cache directory permissions must be `squid:squid`

**Dashboard Issues**
- Must create dashboard user before installing service
- Sudo rules must be configured before starting
- Port 1234 must be available (check conflicts)

## Version History Context

**v1.0** - Initial release
- Plain text password storage (security issue)
- Services ran as root (security issue)
- Dashboard on port 8080

**v2.0** (2026-01-30) - Security hardening
- Removed plain text password storage
- Added input validation
- Dashboard runs as non-root user
- SELinux compatibility
- Dashboard port changed to 1234
- See SECURITY-FIXES.md for full details

## Documentation Philosophy

**Target Audience:** Wide skill range from beginners to advanced users

**Documentation Structure:**
- **README.md** - Complete reference (900+ lines, everything)
- **QUICK-START.md** - Step-by-step for beginners (minimal explanation)
- **TROUBLESHOOTING.md** - Problem/solution format
- **PROJECT-OVERVIEW.md** - Architecture and design rationale
- **SECURITY-FIXES.md** - Security audit results and fixes (v2.0)
- **CONTRIBUTING.md** - Contribution guidelines

**Writing Style:**
- Clear step-by-step instructions
- Heavy use of checkboxes, emojis, visual separators
- Code examples for everything
- Explicit "Before" and "After" comparisons
- Warning boxes for critical steps (Oracle Security List!)

## Testing in Oracle Cloud Free Tier

**Instance Specs:**
- CPU: 4 OCPUs (Ampere Altra ARM)
- RAM: 24 GB
- OS: Oracle Linux 8 (aarch64)
- Network: Up to 1 Gbps

**Performance Expectations:**
- Concurrent connections: 500-1000
- Throughput: 200-500 Mbps
- Latency overhead: 10-50ms

## Related Projects

This project was inspired by similar WireGuard Oracle Linux 8 setup projects. Key differences:
- Proxy server vs VPN tunnel
- Username/password auth vs key-based
- Easier client setup but no encryption at proxy level
- Use HTTPS for end-to-end encryption

## When to Use Each Documentation File

- **Modifying installation scripts** → Reference README.md architecture section
- **Adding security features** → Follow patterns in SECURITY-FIXES.md
- **Writing user-facing docs** → Match tone/style of QUICK-START.md
- **Adding features** → Update all relevant docs (README, QUICK-START, PROJECT-OVERVIEW)
- **Fixing bugs** → Add to TROUBLESHOOTING.md if user-visible

## Port Reference

- **1080** - SOCKS5 proxy (Dante)
- **8888** - HTTP/HTTPS proxy (Squid)
- **1234** - Web dashboard (optional, Python HTTP server)

All ports must be opened in both instance firewall (automated) and Oracle Security List (manual).
