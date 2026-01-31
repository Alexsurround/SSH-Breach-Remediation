# SSH Breach Remediation Guide

## 🚨 Incident Overview

This document describes a real-world SSH breach incident on Debian 10 and provides step-by-step remediation commands.

### Attack Summary
- **Target**: Debian 10 server with user `kodi`
- **Entry Point**: MikroTik router with dst-nat rule exposing SSH port 2223 to the internet
- **Attack Method**: Automated botnet password brute-force
- **Malware**: Cryptocurrency miner disguised as `kauditd0` (legitimate kernel process name)
- **Attack Sources**: Multiple IPs from Netherlands, Germany, China, Russia
- **Persistence**: Cron jobs, SSH authorized_keys, startup scripts

### Initial Symptoms
```bash
# Suspicious process consuming 400-546% CPU
kodi      3800  546  8.2 2433864 2018232 ?     Ssl  14:14   0:54 kauditd0
```

**Red flags**:
- `kauditd0` running as user `kodi` (should be kernel thread)
- Extreme CPU usage (546% = ~5.5 CPU cores)
- Processes `edac0` also running under `kodi` user

---

## 🔍 Initial Investigation

### 1. Check Suspicious Processes
```bash
# View all kodi user processes
sudo ps aux | grep kodi

# Check CPU usage
top -bn1 | head -20
```

### 2. Examine SSH Login History
```bash
# Check successful logins
sudo grep "Accepted password" /var/log/auth.log | grep kodi | tail -30

# Check failed login attempts
sudo grep "Failed password" /var/log/auth.log | grep kodi | tail -20

# Check login history
sudo last -20
```

### 3. Identify Malicious Files
```bash
# Find recently modified files in kodi home directory
sudo find /home/kodi -type f -mtime -7 -ls

# Check for hidden directories
sudo ls -laR /home/kodi/
```

**Discovered malware location**: `/home/kodi/.configrc7/`

### 4. Examine Malware Components
```bash
# View directory structure
sudo ls -la /home/kodi/.configrc7/

# Check SSH keys added by attackers
sudo cat /home/kodi/.ssh/authorized_keys

# Check cron persistence
sudo cat /home/kodi/.configrc7/cron.d
sudo crontab -u kodi -l
```

---

## 🛑 Immediate Response Actions

### 1. Stop SSH Service (Emergency)
```bash
# Stop SSH immediately
sudo systemctl stop sshd

# OR block SSH port with iptables
sudo iptables -A INPUT -p tcp --dport 22 -j DROP
sudo iptables-save
```

### 2. Kill Malicious Processes
```bash
# Kill specific malicious processes
sudo kill -9 3800  # PID of fake kauditd0

# Kill all processes by kodi user
sudo pkill -9 -u kodi

# Kill by process name
sudo killall -9 kauditd0
sudo killall -9 edac0
sudo killall -9 kswapd00
```

### 3. Remove Malware Files
```bash
# Remove malware directory
sudo rm -rf /home/kodi/.configrc7/

# Remove attacker SSH keys
sudo rm -f /home/kodi/.ssh/authorized_keys
sudo rm -rf /home/kodi/.ssh/

# Remove SSL certificates used by malware
sudo rm -f /home/kodi/cert*.pem
```

### 4. Remove Persistence Mechanisms
```bash
# Remove cron jobs
sudo crontab -r -u kodi

# Check and remove from system cron
sudo cat /etc/crontab
sudo ls -la /etc/cron.d/
sudo ls -la /etc/cron.hourly/
sudo ls -la /etc/cron.daily/

# Check for systemd services
sudo systemctl list-units --all | grep kodi
sudo find /etc/systemd -name "*kodi*"
sudo find /home/kodi/.config/systemd -type f 2>/dev/null
```

### 5. Lock Compromised User Account
```bash
# Lock the kodi user password
sudo passwd -l kodi

# Change shell to prevent login
sudo usermod -s /sbin/nologin kodi

# Deny SSH access in sshd_config
echo "DenyUsers kodi" | sudo tee -a /etc/ssh/sshd_config
sudo systemctl restart sshd
```

---

## 🔒 Router Security (MikroTik)

### Fix dst-nat Rule Exposure

#### Via CLI:
```bash
# Connect to MikroTik
ssh admin@router-ip

# List NAT rules
/ip firewall nat print

# Remove the offending dst-nat rule for SSH
/ip firewall nat remove [number]
```

#### Via WinBox:
1. Open WinBox and connect to router
2. Go to **IP → Firewall → NAT**
3. Find rule with `dst-port=22`
4. **Delete** the rule

### Add SSH Brute-Force Protection
```bash
# MikroTik SSH brute-force protection
/ip firewall filter
add chain=input protocol=tcp dst-port=22 src-address-list=ssh_blacklist action=drop comment="Drop SSH blacklisted IPs"
add chain=input protocol=tcp dst-port=22 connection-state=new src-address-list=ssh_stage3 action=add-src-to-address-list address-list=ssh_blacklist address-list-timeout=1w comment="Stage 3: Blacklist"
add chain=input protocol=tcp dst-port=22 connection-state=new src-address-list=ssh_stage2 action=add-src-to-address-list address-list=ssh_stage3 address-list-timeout=1m comment="Stage 2"
add chain=input protocol=tcp dst-port=22 connection-state=new src-address-list=ssh_stage1 action=add-src-to-address-list address-list=ssh_stage2 address-list-timeout=1m comment="Stage 1"
add chain=input protocol=tcp dst-port=22 connection-state=new action=add-src-to-address-list address-list=ssh_stage1 address-list-timeout=1m comment="Detect new SSH connections"
```

---

## 🔐 SSH Server Hardening

### 1. Disable Password Authentication (Use Keys Only)
```bash
# Edit SSH config
sudo nano /etc/ssh/sshd_config
```

Add/modify these lines:
```
PasswordAuthentication no
PermitRootLogin no
PubkeyAuthentication yes
AllowUsers your_admin_user  # NOT kodi
```

### 2. Change SSH Port (Optional)
```bash
# In /etc/ssh/sshd_config
Port 22222  # Use non-standard port
```

### 3. Install Fail2Ban
```bash
# Install fail2ban
sudo apt update
sudo apt install fail2ban -y

# Enable and start
sudo systemctl enable fail2ban
sudo systemctl start fail2ban

# Check status
sudo fail2ban-client status sshd
```

### 4. Restart SSH Service
```bash
sudo systemctl restart sshd
```

---

## 🔬 Deep System Inspection

### 1. Check Running Processes
```bash
# List all processes
ps aux | grep -E "kswapd00|kauditd0|edac0|configrc|init01" | grep -v grep

# Monitor CPU usage
top -bn1 | head -20
htop  # interactive
```

### 2. Check Network Connections
```bash
# Active network connections
sudo netstat -tunap | grep ESTABLISHED
sudo ss -tunap | grep ESTABLISHED

# Listening ports
sudo netstat -tulpn
sudo ss -tulpn
```

### 3. Check Cron Jobs
```bash
# User crontabs
sudo crontab -l
sudo crontab -u kodi -l
sudo crontab -u root -l

# System cron
sudo cat /etc/crontab
sudo ls -la /etc/cron.d/
sudo cat /var/spool/cron/crontabs/*
```

### 4. Check Startup Scripts
```bash
# rc.local (old-style startup)
sudo cat /etc/rc.local

# Bash profile files
sudo cat /home/kodi/.bashrc | tail -20
sudo cat /home/kodi/.profile | tail -20
sudo cat /home/kodi/.bash_profile 2>/dev/null
```

### 5. Search for Remaining Malware
```bash
# Search by filename
sudo find / -name "*kswapd*" 2>/dev/null
sudo find / -name "*configrc*" 2>/dev/null
sudo find / -name "*kauditd*" 2>/dev/null

# Search in temp directories
sudo find /tmp /var/tmp -type f -user kodi 2>/dev/null

# Search for recently modified files
sudo find /home/kodi -type f -mtime -7 -ls
```

### 6. Review Attacker Commands
```bash
# Check bash history to see what attackers did
sudo cat /home/kodi/.bash_history
sudo cat /root/.bash_history
```

---

## 🛡️ Rootkit Detection

### Install Security Tools
```bash
sudo apt update
sudo apt install rkhunter chkrootkit debsums -y
```

### Run Rootkit Scanners
```bash
# rkhunter
sudo rkhunter --update
sudo rkhunter --check --sk

# chkrootkit
sudo chkrootkit

# Verify package integrity
sudo debsums -c | head -50
```

---

## 📊 Verify Cleanup

### 1. Confirm No Suspicious Processes
```bash
ps aux | grep kodi
# Should show no malicious processes
```

### 2. Verify No External Connections
```bash
sudo netstat -tunap | grep ESTABLISHED
# Should show only legitimate connections
```

### 3. Check CPU Usage is Normal
```bash
top -bn1 | head -20
# CPU should be normal (not 400%+)
```

### 4. Verify SSH Not Exposed Externally
```bash
# Get your public IP
curl ifconfig.me

# From another network, scan your IP
nmap -p 22 YOUR_PUBLIC_IP
# Should show: closed or filtered (NOT open)
```

### 5. Verify Cron is Clean
```bash
sudo crontab -l
sudo crontab -u kodi -l  # Should be empty or error
```

---

## ⚠️ Important Recommendations

### Critical: System Reinstallation
After a breach of this magnitude, **the only way to be 100% certain** the system is clean is to:

1. **Backup important data** (not executables)
2. **Reinstall the operating system from scratch**
3. **Restore only data files** (documents, databases, configs)
4. **Never restore** executables, scripts, or binaries from backup

**Why?** Attackers may have installed:
- Kernel-level rootkits
- Modified system binaries
- Hidden backdoors
- Persistent malware you haven't found

### If Reinstallation is Not Possible
At minimum, take these precautions:

1. **Change ALL passwords** on the system
2. **Regenerate all SSH keys**
3. **Monitor system closely** for weeks
4. **Run regular rootkit scans**
5. **Check logs daily** for anomalies
6. **Never fully trust this system** for sensitive operations

---

## 🎯 Prevention Best Practices

### 1. Never Expose SSH Directly to Internet
- **Use VPN** (WireGuard, OpenVPN, L2TP) for remote access
- **Use SSH bastion/jump host** if you must expose SSH
- **Use port knocking** as additional security layer
- **Never use dst-nat** to forward port 22 from WAN

### 2. SSH Hardening
```bash
# /etc/ssh/sshd_config best practices
PermitRootLogin no
PasswordAuthentication no  # Keys only
PubkeyAuthentication yes
Port 22222  # Non-standard port
AllowUsers admin_user  # Whitelist specific users
MaxAuthTries 3
LoginGraceTime 30
```

### 3. Use Strong Authentication
- **SSH keys only** (4096-bit RSA or Ed25519)
- **Long, random passwords** if passwords required
- **Two-factor authentication** (Google Authenticator)

### 4. Install Security Tools
```bash
# Intrusion detection
sudo apt install fail2ban

# Firewall
sudo apt install ufw
sudo ufw enable
sudo ufw allow from YOUR_IP to any port 22

# Log monitoring
sudo apt install logwatch
```

### 5. Regular Security Audits
```bash
# Weekly checks
sudo rkhunter --check
sudo chkrootkit
sudo debsums -c

# Monitor logs
sudo tail -f /var/log/auth.log
sudo grep "Failed password" /var/log/auth.log | tail -50
```

### 6. Network Segmentation
- **Separate management network** from public services
- **VLAN isolation** for critical systems
- **Firewall rules** between network segments

---

## 📝 Attack Timeline (Example from Incident)

```
Jan 31 01:31:59 - First successful login from 91.215.85.88 (Netherlands)
Jan 31 01:33:46 - Login from 185.244.183.190 (Germany)
Jan 31 01:33:52 - Login from 185.173.39.145 (Germany)
Jan 31 01:54:54 - Login from 123.156.230.101 (China)
Jan 31 09:23:42 - Login from 194.163.178.53 (Russia)
Jan 31 14:13:00 - Malware processes spawned
Jan 31 14:14:00 - kauditd0 consuming 546% CPU
Jan 31 14:38:00 - Massive brute-force attempts from multiple IPs
```

**Time to Compromise**: Less than 24 hours after port exposure

---

## 🔗 Useful Resources

- [SSH Best Practices - Mozilla](https://infosec.mozilla.org/guidelines/openssh)
- [CIS Benchmark for Debian](https://www.cisecurity.org/benchmark/debian_linux)
- [fail2ban Documentation](https://www.fail2ban.org/)
- [rkhunter Documentation](http://rkhunter.sourceforge.net/)
- [MikroTik Security](https://wiki.mikrotik.com/wiki/Manual:Securing_Your_Router)

---

## 📧 Contact & Contributions

If you've experienced a similar breach or have additional remediation steps, please contribute!

**Remember**: Security is a process, not a destination. Stay vigilant!

---

## ⚖️ License

This document is provided for educational purposes. Use at your own risk.

**Disclaimer**: Always consult with security professionals for production systems.
