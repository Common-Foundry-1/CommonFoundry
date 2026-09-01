#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
    echo "provision-rcnet-seed.sh must run as root" >&2
    exit 1
fi

admin_user=${1:-cfadmin}
if ! id "${admin_user}" >/dev/null 2>&1; then
    echo "administrator account does not exist: ${admin_user}" >&2
    exit 1
fi
if [[ ! -s /home/${admin_user}/.ssh/authorized_keys ]]; then
    echo "administrator SSH key is absent: ${admin_user}" >&2
    exit 1
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get -y upgrade
apt-get install -y ca-certificates curl jq ufw unattended-upgrades

hostnamectl set-hostname cf-rcnet-seed-01
timedatectl set-timezone UTC

if ! id commonfoundry >/dev/null 2>&1; then
    useradd \
        --system \
        --user-group \
        --home-dir /var/lib/commonfoundry \
        --create-home \
        --shell /usr/sbin/nologin \
        commonfoundry
fi
install -d -m 0755 -o root -g root /opt/commonfoundry /opt/commonfoundry/releases
install -d -m 0750 -o root -g commonfoundry /opt/commonfoundry/artifacts
install -d -m 0750 -o root -g commonfoundry /etc/commonfoundry
install -d -m 0750 -o commonfoundry -g commonfoundry /var/lib/commonfoundry

wallet_passphrase=/etc/commonfoundry/wallet-passphrase
if [[ -L ${wallet_passphrase} || ( -e ${wallet_passphrase} && ! -f ${wallet_passphrase} ) ]]; then
    echo "wallet passphrase path is not a regular file: ${wallet_passphrase}" >&2
    exit 1
fi
if [[ ! -e ${wallet_passphrase} ]]; then
    temporary_passphrase=$(mktemp /etc/commonfoundry/.wallet-passphrase.XXXXXX)
    trap 'rm -f -- "${temporary_passphrase}"' EXIT
    dd if=/dev/urandom bs=48 count=1 status=none | base64 -w 0 >"${temporary_passphrase}"
    printf '\n' >>"${temporary_passphrase}"
    chown root:commonfoundry "${temporary_passphrase}"
    chmod 0640 "${temporary_passphrase}"
    mv -T "${temporary_passphrase}" "${wallet_passphrase}"
    trap - EXIT
fi
chown root:commonfoundry "${wallet_passphrase}"
chmod 0640 "${wallet_passphrase}"

# Contabo's first-boot NoCloud image contains an always-run bootcmd that
# rewrites SSH policy and exits nonzero when its final pkill matches nothing.
# Preserve the remaining standard cloud-init modules but retire that completed
# provider hook after the administrator key has been proven above.
cat >/etc/cloud/cloud.cfg.d/99-commonfoundry-no-bootcmd.cfg <<'EOF'
preserve_hostname: true
cloud_init_modules:
  - seed_random
  - write_files
  - growpart
  - resizefs
  - disk_setup
  - mounts
  - set_hostname
  - update_hostname
  - update_etc_hosts
  - ca_certs
  - rsyslog
  - users_groups
  - ssh
  - set_passwords
EOF
chmod 0644 /etc/cloud/cloud.cfg.d/99-commonfoundry-no-bootcmd.cfg

cat >/etc/ssh/sshd_config.d/00-commonfoundry-hardening.conf <<EOF
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
PermitEmptyPasswords no
X11Forwarding no
AllowUsers ${admin_user}
MaxAuthTries 3
LoginGraceTime 30
EOF
chmod 0644 /etc/ssh/sshd_config.d/00-commonfoundry-hardening.conf
/usr/sbin/sshd -t

passwd -l root >/dev/null
if id ubuntu >/dev/null 2>&1; then
    passwd -l ubuntu >/dev/null
fi

ufw default deny incoming
ufw default allow outgoing
ufw limit 22/tcp
ufw allow 19444/tcp
ufw --force enable

cat >/etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
chmod 0644 /etc/apt/apt.conf.d/20auto-upgrades
systemctl enable --now unattended-upgrades.service
systemctl enable --now fstrim.timer

install -d -m 0755 /etc/systemd/journald.conf.d
cat >/etc/systemd/journald.conf.d/90-commonfoundry-limits.conf <<'EOF'
[Journal]
SystemMaxUse=1G
RuntimeMaxUse=256M
MaxRetentionSec=14day
EOF
chmod 0644 /etc/systemd/journald.conf.d/90-commonfoundry-limits.conf

cat >/usr/local/sbin/commonfoundry-disk-guard <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
usage=$(df -P /var/lib/commonfoundry | awk 'NR == 2 {gsub(/%/, "", $5); print $5}')
available=$(df -PB1 /var/lib/commonfoundry | awk 'NR == 2 {print $4}')
if [[ ! ${usage} =~ ^[0-9]+$ || ! ${available} =~ ^[0-9]+$ ]]; then
    logger -p daemon.err -t commonfoundry-disk-guard "could not inspect node storage"
    exit 1
fi
if (( usage >= 90 )); then
    logger -p daemon.crit -t commonfoundry-disk-guard \
        "CRITICAL node storage usage=${usage}% available_bytes=${available}"
    exit 1
fi
if (( usage >= 75 )); then
    logger -p daemon.warning -t commonfoundry-disk-guard \
        "WARNING node storage usage=${usage}% available_bytes=${available}"
fi
EOF
chmod 0755 /usr/local/sbin/commonfoundry-disk-guard

cat >/etc/systemd/system/commonfoundry-disk-guard.service <<'EOF'
[Unit]
Description=Common Foundry seed-node disk pressure check

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/commonfoundry-disk-guard
EOF

cat >/etc/systemd/system/commonfoundry-disk-guard.timer <<'EOF'
[Unit]
Description=Check Common Foundry seed-node disk pressure hourly

[Timer]
OnBootSec=5min
OnUnitActiveSec=1h
RandomizedDelaySec=5min
Persistent=true

[Install]
WantedBy=timers.target
EOF

install -d -m 0755 /etc/systemd/system/systemd-networkd-wait-online.service.d
cat >/etc/systemd/system/systemd-networkd-wait-online.service.d/90-commonfoundry.conf <<'EOF'
[Service]
ExecStart=
ExecStart=/usr/lib/systemd/systemd-networkd-wait-online --any --timeout=30
EOF

systemctl daemon-reload
systemctl enable --now commonfoundry-disk-guard.timer
systemctl start commonfoundry-disk-guard.service
systemctl restart systemd-journald.service
systemctl reload ssh.service
systemctl reset-failed cloud-init.service systemd-networkd-wait-online.service

echo "Common Foundry seed host provisioning complete"
