# HoneyPot for Cybersecurity Monitoring

This repository contains instructions to deploy and configure **Cowrie**, a medium-interaction SSH and Telnet honeypot, on a VPS for monitoring and analyzing attacker activity.

## Prerequisites
- A VPS (example uses DigitalOcean).
- Root or sudo access to the VPS.
- Basic familiarity with Linux command line and editing files with `nano`/`vim`.

## Step 1: Connect to Your VPS
Replace with your actual VPS IP address:
```bash
ssh root@167.172.238.192
```
Enter the password you created during setup.

## Step 2: Initial VPS Setup
Update and prepare the VPS, create a dedicated cowrie user and install required packages:
```bash
# Update the system
apt update && apt upgrade -y

# Create cowrie user
adduser cowrie
# (Follow prompts to set password and user info)

# Add cowrie to sudo group
usermod -aG sudo cowrie

# Install required packages
apt install git python3-virtualenv libssl-dev libffi-dev build-essential libpython3-dev python3-minimal authbind virtualenv python3-pip python3-venv python3-dev gcc g++ make -y
```

## Step 3: Configure SSH for Admin Access
Edit SSH configuration to change the admin SSH port and restrict users:
```bash
nano /etc/ssh/sshd_config
```
Recommended changes:
- Change `Port 22` to `Port 2222` (or another port for admin access).
- Add `AllowUsers root cowrie` (or adjust to your preferred admin users).

Restart SSH:
```bash
systemctl restart ssh
```

## Step 4: Configure Firewall
Configure `ufw` to allow honeypot and admin access:
```bash
# Honeypot SSH (example)
ufw allow 22/tcp    # Honeypot SSH
ufw allow 23/tcp    # Honeypot Telnet

# If you changed admin SSH to 2222
ufw allow 2222/tcp  # Admin SSH

ufw --force enable

# Check firewall status
ufw status
```

## Step 5: Install Cowrie
Switch to the `cowrie` user, clone Cowrie and install dependencies in a virtualenv:
```bash
su - cowrie

# Clone Cowrie
git clone http://github.com/cowrie/cowrie
cd cowrie

# Create virtual environment
python3 -m venv cowrie-env
source cowrie-env/bin/activate

# Install dependencies
pip install --upgrade pip
pip install --upgrade -r requirements.txt
```

## Step 6: Configure Cowrie
Create the configuration file from the distribution file and edit it:
```bash
cp etc/cowrie.cfg.dist etc/cowrie.cfg
nano etc/cowrie.cfg
```
Important configuration snippets:

SSH section (`[ssh]`):
```ini
[ssh]
listen_endpoints = tcp:2222:interface=0.0.0.0
```

Telnet section (`[telnet]`):
```ini
[telnet]
enabled = true
listen_endpoints = tcp:2323:interface=0.0.0.0
```

Save and exit the editor.

## Step 7: Create Fake User Accounts
Create userdb file with realistic fake credentials:
```bash
cat > etc/userdb.txt << 'EOF'
root:x:root
root:x:123456
root:x:password
admin:x:admin
admin:x:password
user:x:user
test:x:test
guest:x:guest
oracle:x:oracle
*:x:*
EOF
```

## Step 8: Create Fake Filesystem
Create a fake filesystem and populate it with files that look believable to attackers:
```bash
# Navigate to share directory and create fake filesystem
mkdir -p share/cowrie
cd share/cowrie

# Create realistic directory structure
mkdir -p home/{admin,user,test,guest,operator}
mkdir -p home/admin/{Documents,Downloads,Desktop,Pictures}
mkdir -p home/user/{Documents,Downloads}
mkdir -p var/{log,www,lib,cache}
mkdir -p etc/{apache2,mysql,ssh}
mkdir -p usr/{local/bin,share,lib}
mkdir -p opt tmp root

# Create fake sensitive files
echo "admin:$6$salt$hashedpassword" > etc/shadow
echo "database_password=secret123" > etc/mysql/my.cnf
echo "ServerName localhost" > etc/apache2/apache2.conf
echo "127.0.0.1 localhost" > etc/hosts
echo "192.168.1.100 database-server" >> etc/hosts

# Add fake user files
echo "Welcome to the admin account" > home/admin/readme.txt
echo "Personal files and documents" > home/admin/Documents/important.txt

# Create fake scripts
cat > usr/local/bin/backup.sh << 'EOF'
#!/bin/bash
echo "Daily backup script"
echo "Backing up /home to /backup..."
echo "Backup completed at $(date)"
EOF

cat > usr/local/bin/cleanup.sh << 'EOF'
#!/bin/bash
echo "System cleanup script"
echo "Cleaning temporary files..."
echo "Cleanup completed"
EOF

# Make scripts executable
chmod +x usr/local/bin/backup.sh
chmod +x usr/local/bin/cleanup.sh

# Create fake SSH directory with keys
mkdir -p home/admin/.ssh
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ... admin@server" > home/admin/.ssh/authorized_keys
echo "-----BEGIN RSA PRIVATE KEY-----" > home/admin/.ssh/id_rsa
echo "MIIEpAIBAAKCAQEA..." >> home/admin/.ssh/id_rsa
echo "-----END RSA PRIVATE KEY-----" >> home/admin/.ssh/id_rsa
chmod 600 home/admin/.ssh/id_rsa
chmod 644 home/admin/.ssh/authorized_keys
```

## Step 9: Start Cowrie
Start Cowrie and verify status:
```bash
cd ~/cowrie
bin/cowrie start
bin/cowrie status
```

## Step 10: Test the Honeypot
Test SSH interaction locally and from an external host:
```bash
# From the VPS (local)
ssh -p 2222 root@localhost

# From an external machine
ssh -p 2222 root@167.172.238.192
```
Try login attempts using passwords listed in `etc/userdb.txt` (for testing only).

## Step 11: Monitor Your Honeypot Activity
Use Cowrie logs to monitor interactions and collect data for analysis:
```bash
# Watch live activity
tail -f log/cowrie.log

# Check connection attempts
grep -i "connection" log/cowrie.log

# Check authentication attempts
grep -i "login" log/cowrie.log

# View JSON logs for detailed analysis
tail -f log/cowrie.json
```

## Optional Improvements and Notes
- Run Cowrie under a process manager (systemd, supervisor) for automatic restarts.
- Configure log forwarding to a central analysis system (ELK stack, Splunk, or a SIEM).
- Regularly rotate and secure any real admin access keys; never place real private keys in honeypot share directories.
- Consider using `authbind` for binding to privileged ports without running as root.
- Monitor disk and log size; logs can grow quickly in high-traffic environments.
- Adjust firewall and SSH admin port settings to ensure your management accessibility is separate from the honeypot endpoints.

## Security and Ethical Considerations
- Do not use this honeypot to attack others. The honeypot is for observation and analysis only.
- Ensure compliance with local laws and VPS provider terms of service.
- Do not store or expose real user credentials or private data in the honeypot filesystem.
- Isolate the honeypot network where possible (VPC, private networks) to reduce risk of lateral movement.

## License
This repository/documentation is provided as-is for educational and research purposes. Use at your own risk.

## Contact / Further Help
If you want an expanded section about interpreting Cowrie logs, parsing JSON logs for indicators of compromise (IOCs), or integration with SIEM/ELK, tell me which format or tool you prefer and I will include sample commands and dashboards.

## Authors
Walter Carrion [Github](https://github.com/Scopecr), Joshua Santiago [Github](https://github.com/Joshua7792), Hector Rodriguez[Github](https://github.com/fitowashere)