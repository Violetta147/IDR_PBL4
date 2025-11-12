#!/bin/bash
# Script: Disable NIC offload features for accurate packet capture
# Usage: sudo ./disable_nic_offload.sh <interface>

set -e

if [ $# -ne 1 ]; then
    echo "Usage: $0 <interface>"
    echo "Example: $0 eth0"
    exit 1
fi

IFACE=$1

echo "[*] Disabling offload features on $IFACE..."

# Check if interface exists
if ! ip link show "$IFACE" > /dev/null 2>&1; then
    echo "[ERROR] Interface $IFACE does not exist"
    exit 1
fi

# Disable offload features
echo "[*] Disabling TSO (TCP Segmentation Offload)..."
ethtool -K "$IFACE" tso off 2>/dev/null || echo "TSO not supported"

echo "[*] Disabling GSO (Generic Segmentation Offload)..."
ethtool -K "$IFACE" gso off 2>/dev/null || echo "GSO not supported"

echo "[*] Disabling GRO (Generic Receive Offload)..."
ethtool -K "$IFACE" gro off 2>/dev/null || echo "GRO not supported"

echo "[*] Disabling LRO (Large Receive Offload)..."
ethtool -K "$IFACE" lro off 2>/dev/null || echo "LRO not supported"

echo "[*] Disabling TX checksumming..."
ethtool -K "$IFACE" tx off 2>/dev/null || echo "TX checksum not supported"

echo "[*] Disabling RX checksumming..."
ethtool -K "$IFACE" rx off 2>/dev/null || echo "RX checksum not supported"

echo "[*] Disabling scatter-gather..."
ethtool -K "$IFACE" sg off 2>/dev/null || echo "Scatter-gather not supported"

# Display current settings
echo ""
echo "[*] Current offload settings for $IFACE:"
ethtool -k "$IFACE" | grep -E "tcp-segmentation-offload|generic-segmentation-offload|generic-receive-offload|large-receive-offload|tx-checksumming|rx-checksumming|scatter-gather"

echo ""
echo "[✓] Done! Offload features disabled on $IFACE"
echo "[!] Note: These settings will be reset after reboot"
