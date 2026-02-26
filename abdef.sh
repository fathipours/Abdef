#!/usr/bin/env bash
set -euo pipefail

# Abuse Defender - Fixed & Refactored
# Repo: https://github.com/fathipours/Abdef

REPO_RAW_BASE="https://raw.githubusercontent.com/fathipours/Abdef/main"
IP_LIST_URL_V4="${REPO_RAW_BASE}/abuse-ips-ipv4.txt"

CHAIN_MAIN="ABUSE_DEFENDER"
CHAIN_PORTS="ABUSE_PORTS"

SET_BLOCK="abuse_defender_block"
SET_WHITE="abuse_defender_white"
SET_CUSTOM="abuse_defender_custom"

UPDATE_SCRIPT="/root/abdef-update.sh"

pause() { read -r -p "Press Enter to continue..." _; }

check_root() {
  if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
    clear
    echo "You should run this script as root!"
    echo "Tip: sudo -i"
    exit 1
  fi
}

install_dependencies() {
  clear
  echo "Checking dependencies..."

  local updated=false

  if ! command -v apt-get >/dev/null 2>&1; then
    echo "This script currently supports Debian/Ubuntu (apt-get)."
    exit 1
  fi

  if ! command -v curl >/dev/null 2>&1; then
    echo "Installing curl..."
    apt-get update && updated=true
    apt-get install -y curl
  fi

  if ! command -v iptables >/dev/null 2>&1; then
    echo "Installing iptables..."
    if [[ "$updated" == false ]]; then apt-get update && updated=true; fi
    apt-get install -y iptables
  fi

  if ! command -v ipset >/dev/null 2>&1; then
    echo "Installing ipset..."
    if [[ "$updated" == false ]]; then apt-get update && updated=true; fi
    apt-get install -y ipset
  fi

  # Persistent save helpers (optional but useful)
  if ! dpkg -s iptables-persistent >/dev/null 2>&1; then
    echo "Installing iptables-persistent..."
    if [[ "$updated" == false ]]; then apt-get update && updated=true; fi
    DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent
  fi

  if ! dpkg -s ipset-persistent >/dev/null 2>&1; then
    if apt-cache search ipset-persistent | grep -q ipset-persistent; then
      echo "Installing ipset-persistent..."
      if [[ "$updated" == false ]]; then apt-get update && updated=true; fi
      DEBIAN_FRONTEND=noninteractive apt-get install -y ipset-persistent
    fi
  fi
}

setup_ipsets() {
  # hash:net مناسب برای IP و subnet
  ipset create "$SET_BLOCK"  hash:net -exist
  ipset create "$SET_WHITE"  hash:net -exist
  ipset create "$SET_CUSTOM" hash:net -exist
}

allow_loopback() {
  # Loopback باید rule #1 در OUTPUT باشد (برای Xray / dokodemo-door)
  while iptables -C OUTPUT -o lo -j ACCEPT 2>/dev/null; do
    iptables -D OUTPUT -o lo -j ACCEPT
  done
  iptables -I OUTPUT 1 -o lo -j ACCEPT

  # IPv6 loopback (اگر ip6tables موجود بود)
  if command -v ip6tables >/dev/null 2>&1; then
    while ip6tables -C OUTPUT -o lo -j ACCEPT 2>/dev/null; do
      ip6tables -D OUTPUT -o lo -j ACCEPT
    done
    ip6tables -I OUTPUT 1 -o lo -j ACCEPT 2>/dev/null || true
  fi
}

save_rules() {
  if command -v netfilter-persistent >/dev/null 2>&1; then
    netfilter-persistent save || true
  else
    mkdir -p /etc/iptables
    iptables-save > /etc/iptables/rules.v4 || true
    ipset save > /etc/iptables/ipsets || true
  fi
}

setup_chains() {
  # Chain اصلی
  iptables -N "$CHAIN_MAIN" 2>/dev/null || true
  iptables -F "$CHAIN_MAIN"

  # ترتیب: whitelist -> custom drop -> block drop
  iptables -A "$CHAIN_MAIN" -m set --match-set "$SET_WHITE"  dst -j RETURN
  iptables -A "$CHAIN_MAIN" -m set --match-set "$SET_CUSTOM" dst -j DROP
  iptables -A "$CHAIN_MAIN" -m set --match-set "$SET_BLOCK"  dst -j DROP

  # لینک به OUTPUT اگر نبود
  if ! iptables -C OUTPUT -j "$CHAIN_MAIN" 2>/dev/null; then
    iptables -I OUTPUT -j "$CHAIN_MAIN"
  fi

  allow_loopback
}

setup_auto_update() {
  # ساخت اسکریپت آپدیت درست (مشکل اصلی همین heredoc بود)
  cat > "$UPDATE_SCRIPT" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

REPO_RAW_BASE="https://raw.githubusercontent.com/fathipours/Abdef/main"
IP_LIST_URL_V4="${REPO_RAW_BASE}/abuse-ips-ipv4.txt"

TEMP_FILE="/tmp/abuse-ips-update-ipv4.txt"
FILTERED_FILE="/tmp/abuse-ips-filtered-update-ipv4.txt"

SET_BLOCK="abuse_defender_block"

ipset create "$SET_BLOCK" hash:net -exist

if curl -fsSL "$IP_LIST_URL_V4" -o "$TEMP_FILE"; then
  # فیلتر subnetهای خیلی بزرگ مثل /8 (و بزرگتر)
  awk -F'/' '{ if ($2 == "" || $2 > 8) print $0 }' "$TEMP_FILE" > "$FILTERED_FILE"

  ipset flush "$SET_BLOCK"
  awk '{print "add '"$SET_BLOCK"' " $1}' "$FILTERED_FILE" | ipset restore -!

  rm -f "$TEMP_FILE" "$FILTERED_FILE"

  if command -v netfilter-persistent >/dev/null 2>&1; then
    netfilter-persistent save || true
  else
    mkdir -p /etc/iptables
    iptables-save > /etc/iptables/rules.v4 || true
    ipset save > /etc/iptables/ipsets || true
  fi
fi
EOF

  chmod +x "$UPDATE_SCRIPT"

  # کران: روزی یکبار ساعت 00:00
  if ! crontab -l 2>/dev/null | grep -qF "$UPDATE_SCRIPT"; then
    (crontab -l 2>/dev/null; echo "0 0 * * * $UPDATE_SCRIPT") | crontab -
  fi
}

block_ips() {
  clear
  read -r -p "Are you sure about blocking abuse IP-Ranges? [Y/N] : " confirm
  if [[ "$confirm" =~ ^[Yy] ]]; then
    echo "Downloading IP list..."
    local temp="/tmp/abuse-ips-ipv4.txt"
    local filtered="/tmp/abuse-ips-filtered-ipv4.txt"

    if curl -fsSL "$IP_LIST_URL_V4" -o "$temp"; then
      echo "Filtering excessively broad subnets (like /8 and larger)..."
      awk -F'/' '{ if ($2 == "" || $2 > 8) print $0 }' "$temp" > "$filtered"

      echo "Updating ipset '$SET_BLOCK'..."
      ipset flush "$SET_BLOCK"
      awk '{print "add '"$SET_BLOCK"' " $1}' "$filtered" | ipset restore -!

      rm -f "$temp" "$filtered"

      # Idempotent hosts entries (مثل نسخه اصلی)
      grep -qF "127.0.0.1 appclick.co" /etc/hosts || echo "127.0.0.1 appclick.co" >> /etc/hosts
      grep -qF "127.0.0.1 pushnotificationws.com" /etc/hosts || echo "127.0.0.1 pushnotificationws.com" >> /etc/hosts

      save_rules

      read -r -p "Enable Auto-Update every 24 hours? [Y/N] : " enable_update
      if [[ "$enable_update" =~ ^[Yy] ]]; then
        setup_auto_update
        echo "Auto-Update enabled."
      fi

      echo "Abuse IP-Ranges blocked successfully."
    else
      echo "Failed to fetch IP list. Check internet / GitHub access."
    fi

    pause
  else
    echo "Cancelled."
    pause
  fi
}

whitelist_ips() {
  clear
  read -r -p "Enter IP/CIDR to whitelist (e.g., 192.168.1.0/24): " ip_range
  if [[ -z "${ip_range// }" ]]; then
    echo "Input cannot be empty."
  else
    ipset add "$SET_WHITE" "$ip_range" -exist
    echo "$ip_range whitelisted."
    save_rules
  fi
  pause
}

block_custom_ips() {
  clear
  read -r -p "Enter IP/CIDR to block (e.g., 192.168.1.0/24): " ip_range
  if [[ -z "${ip_range// }" ]]; then
    echo "Input cannot be empty."
  else
    ipset add "$SET_CUSTOM" "$ip_range" -exist
    echo "$ip_range blocked."
    save_rules
  fi
  pause
}

block_ports() {
  clear
  read -r -p "Block common abuse ports (25, 137-139, 445) on OUTPUT? [Y/N] : " confirm
  if [[ "$confirm" =~ ^[Yy] ]]; then
    iptables -N "$CHAIN_PORTS" 2>/dev/null || true
    iptables -F "$CHAIN_PORTS"

    echo "Blocking ports 25, 137-139, 445..."
    iptables -A "$CHAIN_PORTS" -p tcp --dport 25 -j DROP
    iptables -A "$CHAIN_PORTS" -p udp --dport 25 -j DROP
    iptables -A "$CHAIN_PORTS" -p tcp --dport 137:139 -j DROP
    iptables -A "$CHAIN_PORTS" -p udp --dport 137:139 -j DROP
    iptables -A "$CHAIN_PORTS" -p tcp --dport 445 -j DROP
    iptables -A "$CHAIN_PORTS" -p udp --dport 445 -j DROP

    if ! iptables -C OUTPUT -j "$CHAIN_PORTS" 2>/dev/null; then
      iptables -I OUTPUT -j "$CHAIN_PORTS"
    fi

    allow_loopback
    save_rules
    echo "Common abuse ports blocked."
  else
    echo "Cancelled."
  fi
  pause
}

view_rules() {
  clear
  echo "===== ${CHAIN_MAIN} Rules ====="
  iptables -L "$CHAIN_MAIN" -n --line-numbers 2>/dev/null || echo "(Chain not found)"

  echo
  if iptables -L "$CHAIN_PORTS" -n >/dev/null 2>&1; then
    echo "===== ${CHAIN_PORTS} Rules ====="
    iptables -L "$CHAIN_PORTS" -n --line-numbers
    echo
  fi

  echo "===== IPSETS ====="
  for s in "$SET_WHITE" "$SET_CUSTOM" "$SET_BLOCK"; do
    if ipset list "$s" >/dev/null 2>&1; then
      local count
      count="$(ipset list "$s" | awk '/Number of entries/ {print $4}')"
      echo "$s: ${count:-0} entries"
    else
      echo "$s: Does not exist"
    fi
  done

  pause
}

clear_chain() {
  clear
  echo "Clearing rules and chains..."

  if iptables -C OUTPUT -j "$CHAIN_MAIN" 2>/dev/null; then
    iptables -D OUTPUT -j "$CHAIN_MAIN"
  fi
  if iptables -C OUTPUT -j "$CHAIN_PORTS" 2>/dev/null; then
    iptables -D OUTPUT -j "$CHAIN_PORTS"
  fi

  iptables -F "$CHAIN_MAIN" 2>/dev/null || true
  iptables -X "$CHAIN_MAIN" 2>/dev/null || true
  iptables -F "$CHAIN_PORTS" 2>/dev/null || true
  iptables -X "$CHAIN_PORTS" 2>/dev/null || true

  ipset destroy "$SET_BLOCK" 2>/dev/null || true
  ipset destroy "$SET_CUSTOM" 2>/dev/null || true
  ipset destroy "$SET_WHITE" 2>/dev/null || true

  sed -i '/127.0.0.1 appclick.co/d' /etc/hosts || true
  sed -i '/127.0.0.1 pushnotificationws.com/d' /etc/hosts || true

  crontab -l 2>/dev/null | grep -vF "$UPDATE_SCRIPT" | crontab - 2>/dev/null || true
  rm -f "$UPDATE_SCRIPT"

  save_rules
  echo "All rules cleared successfully."
  pause
}

main_menu() {
  install_dependencies
  setup_ipsets
  setup_chains

  while true; do
    clear
    echo "----------- Abuse Defender -----------"
    echo "Repo: https://github.com/fathipours/Abdef"
    echo "--------------------------------------"
    echo "Choose an option:"
    echo "1- Block Abuse IP-Ranges"
    echo "2- Whitelist an IP/IP-Range manually"
    echo "3- Block an IP/IP-Range manually"
    echo "4- Block Common Abuse Ports (Netscan/Spam)"
    echo "5- View Rules"
    echo "6- Clear all rules"
    echo "7- Exit"
    echo
    read -r -p "Enter your choice: " choice

    case "$choice" in
      1) block_ips ;;
      2) whitelist_ips ;;
      3) block_custom_ips ;;
      4) block_ports ;;
      5) view_rules ;;
      6) clear_chain ;;
      7) echo "Exiting..."; exit 0 ;;
      *) echo "Invalid option"; pause ;;
    esac
  done
}

check_root
main_menu