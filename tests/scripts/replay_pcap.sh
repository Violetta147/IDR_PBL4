#!/bin/bash
# Script: Replay PCAP file with tcpreplay
# Usage: sudo ./replay_pcap.sh <interface> <pcap_file> [speed_multiplier]

set -e

if [ $# -lt 2 ]; then
    echo "Usage: $0 <interface> <pcap_file> [speed_multiplier]"
    echo "Example: $0 eth0 attack.pcap"
    echo "Example: $0 eth0 attack.pcap 2.0  # 2x speed"
    echo "Example: $0 eth0 attack.pcap 0.5  # half speed"
    exit 1
fi

IFACE=$1
PCAP=$2
SPEED=${3:-1.0}

echo "[*] Replaying $PCAP on $IFACE at ${SPEED}x speed..."

# Check if interface exists
if ! ip link show "$IFACE" > /dev/null 2>&1; then
    echo "[ERROR] Interface $IFACE does not exist"
    exit 1
fi

# Check if PCAP file exists
if [ ! -f "$PCAP" ]; then
    echo "[ERROR] PCAP file $PCAP does not exist"
    exit 1
fi

# Check tcpreplay is installed
if ! command -v tcpreplay &> /dev/null; then
    echo "[ERROR] tcpreplay is not installed"
    echo "Install with: sudo apt-get install tcpreplay"
    exit 1
fi

# Replay with tcpreplay
echo "[*] Starting replay..."
tcpreplay --intf1="$IFACE" --multiplier="$SPEED" --stats=1 "$PCAP"

echo ""
echo "[✓] Replay complete!"
