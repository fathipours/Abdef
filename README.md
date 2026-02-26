# Abuse Defender

An advanced, high-performance, and Xray-compatible Anti-Abuse firewall script for VPN and Proxy servers.

## Features

- **High Performance**: Utilizes `ipset` for efficient IP matching and reduced CPU load.
- **Xray/Marzban Compatible**: Ensures zero interference with loopback traffic and legitimate proxy connections.
- **Anti-Abuse**: Prevents Netscan and Spam by blocking common abuse ports (25, 137-139, 445).
- **Subnet Filtering**: Automatically filters out excessively broad subnets (e.g., /8) to prevent false positives.
- **Auto-Update**: Includes an optional cronjob to keep the abuse IP list up-to-date.
- **Idempotent**: Safe to run multiple times without duplicating rules.

## Installation

Run the following command to install and start the script:

```bash
sudo bash -c "$(curl -sL https://raw.githubusercontent.com/fathipours/AbDef/main/abdef.sh)"
```
