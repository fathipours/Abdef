#!/bin/bash

# Abuse Defender - Refactored
# https://github.com/fathipours/AbDef

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        clear
        echo "You should run this script with root!"
        echo "Use sudo -i to change user to root"
        exit 1
    fi
}

check_root

install_dependencies() {
    clear
    echo "Checking dependencies..."
    local updated=false

    if ! command -v curl &> /dev/null; then
        echo "Installing curl..."
        apt-get update && updated=true
        apt-get install -y curl
    fi

    if ! command -v iptables &> /dev/null; then
        echo "Installing iptables..."
        if [ "$updated" = false ]; then apt-get update && updated=true; fi
        apt-get install -y iptables
    fi

    if ! command -v ipset &> /dev/null; then
        echo "Installing ipset..."
        if [ "$updated" = false ]; then apt-get update && updated=true; fi
        apt-get install -y ipset
    fi

    if ! dpkg -s iptables-persistent &> /dev/null; then
        echo "Installing iptables-persistent..."
        if [ "$updated" = false ]; then apt-get update && updated=true; fi
        DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent
    fi

    # Try to install ipset-persistent if available
    if ! dpkg -s ipset-persistent &> /dev/null; then
         if apt-cache search ipset-persistent | grep -q ipset-persistent; then
             echo "Installing ipset-persistent..."
             if [ "$updated" = false ]; then apt-get update && updated=true; fi
             DEBIAN_FRONTEND=noninteractive apt-get install -y ipset-persistent
         fi
    fi
}

setup_ipsets() {
    # Create ipsets if they don't exist
    # hash:net is suitable for storing subnets and IP addresses
    if command -v ipset >/dev/null; then
        ipset create abuse_defender_block hash:net -exist
        ipset create abuse_defender_white hash:net -exist
        ipset create abuse_defender_custom hash:net -exist
    fi
}

allow_loopback() {
    # Ensure loopback is allowed at the top of OUTPUT (Required for Xray/Dokodemo-door)
    # We remove and re-insert to guarantee it is rule #1
    while iptables -C OUTPUT -o lo -j ACCEPT 2>/dev/null; do
        iptables -D OUTPUT -o lo -j ACCEPT
    done
    iptables -I OUTPUT 1 -o lo -j ACCEPT

    # Also ensure loopback for IPv6 if available
    if command -v ip6tables >/dev/null; then
        while ip6tables -C OUTPUT -o lo -j ACCEPT 2>/dev/null; do
             ip6tables -D OUTPUT -o lo -j ACCEPT
        done
        ip6tables -I OUTPUT 1 -o lo -j ACCEPT 2>/dev/null || true
    fi
}

save_rules() {
    if command -v netfilter-persistent >/dev/null; then
        netfilter-persistent save
    elif command -v iptables-save >/dev/null; then
        mkdir -p /etc/iptables
        iptables-save > /etc/iptables/rules.v4
        if command -v ipset >/dev/null; then
             ipset save > /etc/iptables/ipsets
        fi
    fi
}

setup_auto_update() {
    # Create update script that re-downloads list and updates ipset
    cat <<EOF >/root/abdef-update.sh
#!/bin/bash
# Auto-update script for Abuse Defender
IP_LIST_URL="https://raw.githubusercontent.com/fathipours/AbDef/main/abuse-ips-ipv4.txt"
TEMP_FILE="/tmp/abuse-ips-update-ipv4.txt"
FILTERED_FILE="/tmp/abuse-ips-filtered-update-ipv4.txt"

# Ensure ipset exists
ipset create abuse_defender_block hash:net -exist

if curl -s "\$IP_LIST_URL" -o "\$TEMP_FILE"; then
    awk -F'/' '{ if (\$2 == "" || \$2 > 8) print \$0 }' "\$TEMP_FILE" > "\$FILTERED_FILE"

    # Flush and restore
    ipset flush abuse_defender_block
    awk '{print "add abuse_defender_block " \$1}' "\$FILTERED_FILE" | ipset restore -!

    rm -f "\$TEMP_FILE" "\$FILTERED_FILE"

    # Save state
    if command -v netfilter-persistent >/dev/null; then
        netfilter-persistent save
    else
        iptables-save > /etc/iptables/rules.v4
        ipset save > /etc/iptables/ipsets
    fi
fi
EOF
    chmod +x /root/abdef-update.sh

    # Add to crontab if not exists
    if ! crontab -l 2>/dev/null | grep -q "/root/abdef-update.sh"; then
        (crontab -l 2>/dev/null; echo "0 0 * * * /root/abdef-update.sh") | crontab -
    fi
}

setup_chains() {
    # Ensure our custom chain exists
    if ! iptables -N ABUSE_DEFENDER 2>/dev/null; then
        # Chain might already exist
        :
    fi

    # Flush and recreate rules in ABUSE_DEFENDER to ensure correct order
    iptables -F ABUSE_DEFENDER

    iptables -A ABUSE_DEFENDER -m set --match-set abuse_defender_white dst -j RETURN
    iptables -A ABUSE_DEFENDER -m set --match-set abuse_defender_custom dst -j DROP
    iptables -A ABUSE_DEFENDER -m set --match-set abuse_defender_block dst -j DROP

    # Link to OUTPUT if not already linked
    if ! iptables -C OUTPUT -j ABUSE_DEFENDER 2>/dev/null; then
        iptables -I OUTPUT -j ABUSE_DEFENDER
    fi

    # Ensure loopback is always whitelisted first (must run after linking chains)
    allow_loopback
}

main_menu() {
    install_dependencies
    setup_ipsets
    setup_chains
    while true; do
        clear
        echo "----------- Abuse Defender -----------"
        echo "https://github.com/fathipours/AbDef"
        echo "--------------------------------------"
        echo "Choose an option:"
        echo "1-Block Abuse IP-Ranges"
        echo "2-Whitelist an IP/IP-Ranges manually"
        echo "3-Block an IP/IP-Ranges manually"
        echo "4-Block Common Abuse Ports (Netscan/Spam)"
        echo "5-View Rules"
        echo "6-Clear all rules"
        echo "7-Exit"
        read -p "Enter your choice: " choice
        case $choice in
            1) block_ips ;;
            2) whitelist_ips ;;
            3) block_custom_ips ;;
            4) block_ports ;;
            5) view_rules ;;
            6) clear_chain ;;
            7) echo "Exiting..."; exit 0 ;;
            *) echo "Invalid option"; read -p "Press Enter to continue" ;;
        esac
    done
}

block_ips() {
    clear
    read -p "Are you sure about blocking abuse IP-Ranges? [Y/N] : " confirm

    if [[ $confirm == [Yy]* ]]; then
        echo "Downloading IP list..."
        local IP_LIST_URL="https://raw.githubusercontent.com/fathipours/AbDef/main/abuse-ips.ipv4"
        local TEMP_FILE="/tmp/abuse-ips.ipv4"

        if curl -s "$IP_LIST_URL" -o "$TEMP_FILE"; then
            echo "Filtering excessively broad subnets (like /8)..."
            local FILTERED_FILE="/tmp/abuse-ips-filtered.ipv4"
            # Filter: Keep if no slash (implied /32) OR if prefix > 8
            awk -F'/' '{ if ($2 == "" || $2 > 8) print $0 }' "$TEMP_FILE" > "$FILTERED_FILE"

            echo "Updating ipset 'abuse_defender_block'..."
            ipset flush abuse_defender_block

            # specific format for ipset restore: add <setname> <entry>
            # -!: ignore errors (e.g. duplicates if any, though we flushed)
            awk '{print "add abuse_defender_block " $1}' "$FILTERED_FILE" | ipset restore -!

            echo "Abuse IP-Ranges blocked successfully."

            rm -f "$TEMP_FILE" "$FILTERED_FILE"

            # Idempotent hosts modifications
            if ! grep -q "127.0.0.1 appclick.co" /etc/hosts; then
                echo '127.0.0.1 appclick.co' >> /etc/hosts
            fi
            if ! grep -q "127.0.0.1 pushnotificationws.com" /etc/hosts; then
                echo '127.0.0.1 pushnotificationws.com' >> /etc/hosts
            fi

            save_rules

            read -p "Do you want to enable Auto-Update every 24 hours? [Y/N] : " enable_update
            if [[ $enable_update == [Yy]* ]]; then
                setup_auto_update
                echo "Auto-Update has been enabled."
            fi
        else
            echo "Failed to fetch IP list. Check your internet connection."
        fi
        read -p "Press Enter to return to Menu" dummy
    else
        echo "Cancelled."
        read -p "Press Enter to return to Menu" dummy
    fi
}

whitelist_ips() {
    clear
    read -p "Enter IP/CIDR to whitelist (e.g., 192.168.1.0/24): " ip_range
    if [[ -z "$ip_range" ]]; then
        echo "Input cannot be empty."
    else
        ipset add abuse_defender_white "$ip_range" -exist
        echo "$ip_range whitelisted."
        save_rules
    fi
    read -p "Press Enter to return to Menu" dummy
}

block_custom_ips() {
    clear
    read -p "Enter IP/CIDR to block (e.g., 192.168.1.0/24): " ip_range
    if [[ -z "$ip_range" ]]; then
        echo "Input cannot be empty."
    else
        ipset add abuse_defender_custom "$ip_range" -exist
        echo "$ip_range blocked."
        save_rules
    fi
    read -p "Press Enter to return to Menu" dummy
}

block_ports() {
    clear
    read -p "Do you want to block common abuse ports (25, 137-139, 445) on OUTPUT? [Y/N] : " confirm
    if [[ $confirm == [Yy]* ]]; then
        # Create chain if needed
        if ! iptables -N ABUSE_PORTS 2>/dev/null; then
             :
        fi

        # Flush to avoid duplicates
        iptables -F ABUSE_PORTS

        echo "Blocking ports 25, 137, 138, 139, 445..."
        iptables -A ABUSE_PORTS -p tcp --dport 25 -j DROP
        iptables -A ABUSE_PORTS -p udp --dport 25 -j DROP
        iptables -A ABUSE_PORTS -p tcp --dport 137:139 -j DROP
        iptables -A ABUSE_PORTS -p udp --dport 137:139 -j DROP
        iptables -A ABUSE_PORTS -p tcp --dport 445 -j DROP
        iptables -A ABUSE_PORTS -p udp --dport 445 -j DROP

        # Link to OUTPUT if not already linked
        if ! iptables -C OUTPUT -j ABUSE_PORTS 2>/dev/null; then
            iptables -I OUTPUT -j ABUSE_PORTS
        fi

        # Ensure loopback stays on top
        allow_loopback

        save_rules
        echo "Common abuse ports blocked."
    else
        echo "Cancelled."
    fi
    read -p "Press Enter to return to Menu" dummy
}

view_rules() {
    clear
    echo "===== ABUSE_DEFENDER Rules ====="
    iptables -L ABUSE_DEFENDER -n --line-numbers 2>/dev/null
    echo ""
    if iptables -L ABUSE_PORTS -n >/dev/null 2>&1; then
        echo "===== ABUSE_PORTS Rules ====="
        iptables -L ABUSE_PORTS -n --line-numbers
        echo ""
    fi

    echo "===== IPSETS ====="
    if command -v ipset >/dev/null; then
        # Check if sets exist before listing
        for set in abuse_defender_white abuse_defender_custom abuse_defender_block; do
             if ipset list "$set" >/dev/null 2>&1; then
                 count=$(ipset list "$set" | grep "Number of entries" | awk '{print $4}')
                 echo "$set: $count entries"
             else
                 echo "$set: Does not exist"
             fi
        done
    else
        echo "ipset command not found."
    fi

    read -p "Press Enter to return to Menu" dummy
}

clear_chain() {
    clear
    echo "Clearing rules and chains..."

    # Unlink chains from OUTPUT
    if iptables -C OUTPUT -j ABUSE_DEFENDER 2>/dev/null; then
        iptables -D OUTPUT -j ABUSE_DEFENDER
    fi
    if iptables -C OUTPUT -j ABUSE_PORTS 2>/dev/null; then
        iptables -D OUTPUT -j ABUSE_PORTS
    fi

    # Flush and Delete Chains
    iptables -F ABUSE_DEFENDER 2>/dev/null
    iptables -X ABUSE_DEFENDER 2>/dev/null
    iptables -F ABUSE_PORTS 2>/dev/null
    iptables -X ABUSE_PORTS 2>/dev/null

    # Destroy IP Sets
    if command -v ipset >/dev/null; then
        ipset destroy abuse_defender_block 2>/dev/null
        ipset destroy abuse_defender_custom 2>/dev/null
        ipset destroy abuse_defender_white 2>/dev/null
    fi

    # Hosts cleanup
    sed -i '/127.0.0.1 appclick.co/d' /etc/hosts
    sed -i '/127.0.0.1 pushnotificationws.com/d' /etc/hosts

    # Crontab cleanup
    crontab -l 2>/dev/null | grep -v "/root/abdef-update.sh" | grep -v "/root/abuse-defender-update.sh" | crontab -

    # Remove update script
    rm -f /root/abdef-update.sh
    rm -f /root/abuse-defender-update.sh

    save_rules

    echo "All Rules cleared successfully."
    read -p "Press Enter to return to Menu" dummy
}
