#!/bin/bash
# Script: Complete IDS testing workflow
# Usage: sudo ./ids_test_workflow.sh <interface> <test_pcap>

set -e

if [ $# -ne 2 ]; then
    echo "Usage: $0 <interface> <test_pcap>"
    echo "Example: $0 eth0 test_sqli.pcap"
    exit 1
fi

IFACE=$1
TEST_PCAP=$2
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=========================================="
echo "IDS Testing Workflow"
echo "=========================================="
echo "Interface: $IFACE"
echo "Test PCAP: $TEST_PCAP"
echo ""

# Step 1: Disable offload
echo "[Step 1/4] Disabling NIC offload..."
bash "$SCRIPT_DIR/disable_nic_offload.sh" "$IFACE"
sleep 2

# Step 2: Clear old logs
echo ""
echo "[Step 2/4] Clearing old IDS logs..."
rm -f app/logs/traffic.log app/logs/alerts.log
echo "[✓] Logs cleared"

# Step 3: Start IDS in background
echo ""
echo "[Step 3/4] Starting IDS..."
sudo python app/capture_packet/ids_byte_deep.py \
    --iface "$IFACE" \
    --filter "tcp port 80 or tcp port 443" \
    --payload-bytes 8192 \
    --verbose > /tmp/ids_output.log 2>&1 &
IDS_PID=$!
echo "[✓] IDS started (PID: $IDS_PID)"
sleep 3

# Step 4: Replay test PCAP
echo ""
echo "[Step 4/4] Replaying test PCAP..."
bash "$SCRIPT_DIR/replay_pcap.sh" "$IFACE" "$TEST_PCAP" 1.0

# Wait a bit for IDS to process
sleep 5

# Stop IDS
echo ""
echo "[*] Stopping IDS..."
kill -INT $IDS_PID 2>/dev/null || true
wait $IDS_PID 2>/dev/null || true

# Show results
echo ""
echo "=========================================="
echo "Test Results"
echo "=========================================="
echo "[*] Alerts generated:"
if [ -f app/logs/alerts.log ]; then
    grep -c "ALERT" app/logs/alerts.log || echo "0"
else
    echo "0 (no alerts.log file)"
fi

echo ""
echo "[*] Sample alerts (last 10):"
if [ -f app/logs/alerts.log ]; then
    tail -n 10 app/logs/alerts.log
else
    echo "(no alerts)"
fi

echo ""
echo "[✓] Test complete!"
echo "[*] Full IDS output: /tmp/ids_output.log"
echo "[*] Alerts log: app/logs/alerts.log"
echo "[*] Traffic log: app/logs/traffic.log"
