#!/bin/bash
# Script: Capture network traffic to PCAP file
# Usage: sudo ./capture_pcap.sh <interface> <output_file> [filter]

set -e

if [ $# -lt 2 ]; then
    echo "Usage: $0 <interface> <output_file> [filter]"
    echo "Example: $0 eth0 capture.pcap"
    echo "Example: $0 eth0 http_traffic.pcap 'tcp port 80'"
    exit 1
fi

IFACE=$1
OUTPUT=$2
FILTER=${3:-""}
DURATION=60  # Capture duration in seconds

echo "[*] Starting packet capture on $IFACE..."
echo "[*] Output file: $OUTPUT"
echo "[*] Filter: ${FILTER:-'(no filter)'}"
echo "[*] Duration: $DURATION seconds"

# Check if interface exists
if ! ip link show "$IFACE" > /dev/null 2>&1; then
    echo "[ERROR] Interface $IFACE does not exist"
    exit 1
fi

# Capture with tcpdump
if [ -z "$FILTER" ]; then
    timeout $DURATION tcpdump -i "$IFACE" -w "$OUTPUT" -nn -s 65535
else
    timeout $DURATION tcpdump -i "$IFACE" -w "$OUTPUT" -nn -s 65535 "$FILTER"
fi

echo ""
echo "[✓] Capture complete!"
echo "[*] File: $OUTPUT"
echo "[*] Size: $(du -h "$OUTPUT" | cut -f1)"
echo "[*] Packet count: $(tcpdump -r "$OUTPUT" 2>/dev/null | wc -l)"
