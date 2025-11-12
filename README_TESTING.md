# Hướng Dẫn Testing IDS - Test Plan Implementation

## Mục Lục
1. [Giới thiệu](#giới-thiệu)
2. [Môi trường test](#môi-trường-test)
3. [Test PCAP Files](#test-pcap-files)
4. [Chạy Tests](#chạy-tests)
5. [Interpret Results](#interpret-results)
6. [Troubleshooting](#troubleshooting)

---

## Giới thiệu

Document này mô tả cách chạy tests để validate các fix cho false positive trong TCP stream detection.

### Test Coverage
- ✅ TCP reassembly (out-of-order, retrans, overlapping)
- ✅ Duplicate detection
- ✅ Connection tracking và cleanup
- ✅ Performance under load
- ✅ Edge cases (SYN flood, asymmetric flow, connection reuse)

---

## Môi trường test

### Prerequisites
```bash
# Install dependencies
sudo apt-get update
sudo apt-get install -y \
    python3 \
    python3-pip \
    tcpdump \
    tcpreplay \
    ethtool \
    scapy

# Install Python packages
pip3 install -r requirements.txt
```

### Setup Test Environment
```bash
# 1. Create virtual environment (optional but recommended)
python3 -m venv .venv
source .venv/bin/activate

# 2. Verify ethtool is available (for NIC offload disable)
which ethtool || sudo apt-get install ethtool

# 3. Verify tcpreplay is available
which tcpreplay || sudo apt-get install tcpreplay

# 4. Create test interface (loopback or dummy)
# Option A: Use loopback (lo)
# - Pros: Always available
# - Cons: Cannot use tcpreplay (needs different approach)

# Option B: Create dummy interface
sudo ip link add dummy0 type dummy
sudo ip link set dummy0 up
sudo ip addr add 192.168.100.1/24 dev dummy0

# 5. Disable offload on test interface
sudo bash tests/scripts/disable_nic_offload.sh dummy0
```

---

## Test PCAP Files

### 1. Test Out-of-Order Segments
**File**: `tests/pcaps/test_out_of_order.pcap`

**Mô tả**: HTTP request với SQLi payload, segments gửi không theo thứ tự (1,3,5,2,4)

**Tạo PCAP (với Scapy)**:
```python
#!/usr/bin/env python3
from scapy.all import *

# Packet 1: SYN
p1 = Ether()/IP(src="192.168.1.100", dst="192.168.1.200")/TCP(sport=12345, dport=80, flags="S", seq=1000)

# Packet 2: SYN-ACK
p2 = Ether()/IP(src="192.168.1.200", dst="192.168.1.100")/TCP(sport=80, dport=12345, flags="SA", seq=2000, ack=1001)

# Packet 3: ACK
p3 = Ether()/IP(src="192.168.1.100", dst="192.168.1.200")/TCP(sport=12345, dport=80, flags="A", seq=1001, ack=2001)

# HTTP request với SQLi - split thành 5 segments
payload = b"GET /admin?id=1' UNION SELECT * FROM users-- HTTP/1.1\r\nHost: example.com\r\n\r\n"
seg1 = payload[0:20]   # "GET /admin?id=1' UNI"
seg2 = payload[20:40]  # "ON SELECT * FROM use"
seg3 = payload[40:60]  # "rs-- HTTP/1.1\r\nHost:"
seg4 = payload[60:80]  # " example.com\r\n\r\n"
seg5 = payload[80:]    # (remaining)

# Send in order: 1, 3, 5, 2, 4 (out of order!)
p4 = Ether()/IP(src="192.168.1.100", dst="192.168.1.200")/TCP(sport=12345, dport=80, flags="PA", seq=1001, ack=2001)/Raw(load=seg1)
p5 = Ether()/IP(src="192.168.1.100", dst="192.168.1.200")/TCP(sport=12345, dport=80, flags="PA", seq=1041, ack=2001)/Raw(load=seg3)  # Out of order!
p6 = Ether()/IP(src="192.168.1.100", dst="192.168.1.200")/TCP(sport=12345, dport=80, flags="PA", seq=1061, ack=2001)/Raw(load=seg5)  # Out of order!
p7 = Ether()/IP(src="192.168.1.100", dst="192.168.1.200")/TCP(sport=12345, dport=80, flags="PA", seq=1021, ack=2001)/Raw(load=seg2)  # Missing segment
p8 = Ether()/IP(src="192.168.1.100", dst="192.168.1.200")/TCP(sport=12345, dport=80, flags="PA", seq=1061, ack=2001)/Raw(load=seg4)

# FIN
p9 = Ether()/IP(src="192.168.1.100", dst="192.168.1.200")/TCP(sport=12345, dport=80, flags="FA", seq=1081, ack=2001)

wrpcap("tests/pcaps/test_out_of_order.pcap", [p1,p2,p3,p4,p5,p6,p7,p8,p9])
print("[✓] Created test_out_of_order.pcap")
```

**Expected Result**: 1 alert khi reassemble xong (không phải 5 alerts riêng lẻ)

### 2. Test Retransmission
**File**: `tests/pcaps/test_retransmission.pcap`

**Mô tả**: HTTP request bình thường nhưng có retransmissions

```python
#!/usr/bin/env python3
from scapy.all import *

packets = []

# 3-way handshake
packets.append(Ether()/IP(src="192.168.1.100", dst="192.168.1.200")/TCP(sport=12345, dport=80, flags="S", seq=1000))
packets.append(Ether()/IP(src="192.168.1.200", dst="192.168.1.100")/TCP(sport=80, dport=12345, flags="SA", seq=2000, ack=1001))
packets.append(Ether()/IP(src="192.168.1.100", dst="192.168.1.200")/TCP(sport=12345, dport=80, flags="A", seq=1001, ack=2001))

# HTTP request - segment 1
payload1 = b"GET /test HTTP/1.1\r\n"
packets.append(Ether()/IP(src="192.168.1.100", dst="192.168.1.200")/TCP(sport=12345, dport=80, flags="PA", seq=1001, ack=2001)/Raw(load=payload1))

# Retransmission của segment 1 (same seq, same data)
packets.append(Ether()/IP(src="192.168.1.100", dst="192.168.1.200")/TCP(sport=12345, dport=80, flags="PA", seq=1001, ack=2001)/Raw(load=payload1))

# Segment 2
payload2 = b"Host: example.com\r\n\r\n"
packets.append(Ether()/IP(src="192.168.1.100", dst="192.168.1.200")/TCP(sport=12345, dport=80, flags="PA", seq=1001+len(payload1), ack=2001)/Raw(load=payload2))

# FIN
packets.append(Ether()/IP(src="192.168.1.100", dst="192.168.1.200")/TCP(sport=12345, dport=80, flags="FA", seq=1001+len(payload1)+len(payload2), ack=2001))

wrpcap("tests/pcaps/test_retransmission.pcap", packets)
print("[✓] Created test_retransmission.pcap")
```

**Expected Result**: 0 alerts (normal traffic), không log duplicate cho retransmission

### 3. Test Overlapping Segments
**File**: `tests/pcaps/test_overlapping.pcap`

**Mô tả**: TCP segments overlap một phần

```python
#!/usr/bin/env python3
from scapy.all import *

packets = []

# Handshake
packets.append(Ether()/IP(src="192.168.1.100", dst="192.168.1.200")/TCP(sport=12345, dport=80, flags="S", seq=1000))
packets.append(Ether()/IP(src="192.168.1.200", dst="192.168.1.100")/TCP(sport=80, dport=12345, flags="SA", seq=2000, ack=1001))
packets.append(Ether()/IP(src="192.168.1.100", dst="192.168.1.200")/TCP(sport=12345, dport=80, flags="A", seq=1001, ack=2001))

# Segment 1: "SELECT * FROM users WHERE"
seg1 = b"SELECT * FROM users WHERE"
packets.append(Ether()/IP(src="192.168.1.100", dst="192.168.1.200")/TCP(sport=12345, dport=80, flags="PA", seq=1001, ack=2001)/Raw(load=seg1))

# Segment 2: OVERLAP - "S WHERE id=1" (overlaps last 8 bytes of seg1)
seg2 = b"S WHERE id=1"
packets.append(Ether()/IP(src="192.168.1.100", dst="192.168.1.200")/TCP(sport=12345, dport=80, flags="PA", seq=1001+len(seg1)-8, ack=2001)/Raw(load=seg2))

# FIN
packets.append(Ether()/IP(src="192.168.1.100", dst="192.168.1.200")/TCP(sport=12345, dport=80, flags="FA", seq=1001+len(seg1)+len(seg2)-8, ack=2001))

wrpcap("tests/pcaps/test_overlapping.pcap", packets)
print("[✓] Created test_overlapping.pcap")
```

**Expected Result**: 1 alert (SQLi detected), reassemble không bị corrupt

### 4-10. Other Test PCAPs
Tương tự, tạo các PCAP files khác theo test plan (xem PHAN_TICH_FALSE_POSITIVE.md section 4).

**Script tự động tạo tất cả test PCAPs**:
```bash
#!/bin/bash
# File: tests/scripts/generate_test_pcaps.sh

python3 tests/pcap_generators/generate_out_of_order.py
python3 tests/pcap_generators/generate_retransmission.py
python3 tests/pcap_generators/generate_overlapping.py
python3 tests/pcap_generators/generate_large_payload.py
python3 tests/pcap_generators/generate_syn_flood.py
python3 tests/pcap_generators/generate_asymmetric.py
python3 tests/pcap_generators/generate_connection_reuse.py
python3 tests/pcap_generators/generate_base64.py
python3 tests/pcap_generators/generate_keep_alive.py
python3 tests/pcap_generators/generate_fast_retransmit.py

echo "[✓] All test PCAPs generated in tests/pcaps/"
```

---

## Chạy Tests

### Quick Test (Single PCAP)
```bash
# Test với 1 PCAP file
sudo bash tests/scripts/ids_test_workflow.sh lo tests/pcaps/test_out_of_order.pcap
```

### Full Test Suite
```bash
#!/bin/bash
# File: tests/scripts/run_all_tests.sh

IFACE="lo"
PCAP_DIR="tests/pcaps"
RESULTS_DIR="tests/results"

mkdir -p "$RESULTS_DIR"

echo "=========================================="
echo "Running IDS Full Test Suite"
echo "=========================================="

for pcap in "$PCAP_DIR"/*.pcap; do
    echo ""
    echo "[*] Testing: $(basename $pcap)"
    
    # Clear logs
    rm -f app/logs/alerts.log app/logs/traffic.log
    
    # Run test
    bash tests/scripts/ids_test_workflow.sh "$IFACE" "$pcap" > "$RESULTS_DIR/$(basename $pcap .pcap).log" 2>&1
    
    # Extract results
    alert_count=$(grep -c "ALERT" app/logs/alerts.log 2>/dev/null || echo "0")
    echo "  - Alerts: $alert_count"
    
    # Copy logs
    cp app/logs/alerts.log "$RESULTS_DIR/$(basename $pcap .pcap)_alerts.log" 2>/dev/null || true
done

echo ""
echo "=========================================="
echo "Test Suite Complete"
echo "=========================================="
echo "[*] Results saved in: $RESULTS_DIR/"
```

### Automated Testing với pytest
```python
# File: tests/test_pcap_replay.py

import pytest
import subprocess
import os
import time

PCAP_DIR = "tests/pcaps"
SCRIPT = "tests/scripts/ids_test_workflow.sh"
IFACE = "lo"

test_cases = [
    ("test_out_of_order.pcap", 1, "Out-of-order segments should generate 1 alert"),
    ("test_retransmission.pcap", 0, "Retransmissions should not generate alerts"),
    ("test_overlapping.pcap", 1, "Overlapping segments should generate 1 alert"),
    # Add more test cases...
]

@pytest.mark.parametrize("pcap,expected_alerts,description", test_cases)
def test_pcap_replay(pcap, expected_alerts, description):
    """Test IDS with PCAP replay"""
    pcap_path = os.path.join(PCAP_DIR, pcap)
    
    # Clear old logs
    try:
        os.remove("app/logs/alerts.log")
    except FileNotFoundError:
        pass
    
    # Run test
    result = subprocess.run(
        ["sudo", "bash", SCRIPT, IFACE, pcap_path],
        capture_output=True,
        text=True,
        timeout=60
    )
    
    # Count alerts
    try:
        with open("app/logs/alerts.log") as f:
            alert_count = sum(1 for line in f if "ALERT" in line)
    except FileNotFoundError:
        alert_count = 0
    
    # Assert
    assert alert_count == expected_alerts, f"{description} - Expected {expected_alerts} alerts, got {alert_count}"

# Run with: sudo pytest tests/test_pcap_replay.py -v
```

---

## Interpret Results

### Expected Results Summary

| Test PCAP | Scenario | Expected Alerts | False Positive? |
|-----------|----------|----------------|-----------------|
| test_out_of_order.pcap | Out-of-order segments | 1 | No |
| test_retransmission.pcap | TCP retrans | 0 | No |
| test_overlapping.pcap | Overlapping segments | 1 | No |
| test_large_payload.pcap | IP frag + TCP seg | 1 | No |
| test_syn_flood.pcap | SYN flood | 0-10* | No |
| test_asymmetric.pcap | One-way flow | 1 | No |
| test_connection_reuse.pcap | Same 4-tuple | 1 | No |
| test_base64.pcap | Legit Base64 | 1 | Yes (expected)** |
| test_keep_alive.pcap | HTTP keep-alive | 1 | No |
| test_fast_retransmit.pcap | Fast retrans | 1 | No |

\* SYN flood có thể trigger một vài alerts cho rate-based rules (nếu có)  
\** Base64 test case là để verify rule không over-trigger, expected 1 alert cho actual SQLi payload

### Metrics để track

#### 1. Alert Count
```bash
# Count total alerts
grep -c "ALERT" app/logs/alerts.log

# Count alerts by rule ID
grep "ALERT" app/logs/alerts.log | awk '{print $3}' | sort | uniq -c
```

#### 2. Duplicate Detection
```bash
# Find duplicate alerts (same src, dst, rule within 60s)
# This is complex, better to use a Python script

python3 <<EOF
import re
from datetime import datetime

alerts = []
with open("app/logs/alerts.log") as f:
    for line in f:
        if "ALERT" not in line:
            continue
        # Parse alert line
        # Format: timestamp [ALERT] [rule_id] message | proto=... src:port->dst:port
        # Example: 2023-10-01 12:34:56 [ALERT] [SQLI_C-UNION-001] SQLi detected | proto=TCP 192.168.1.100:12345->192.168.1.200:80
        # Extract key info
        parts = line.split()
        timestamp = datetime.strptime(f"{parts[0]} {parts[1]}", "%Y-%m-%d %H:%M:%S")
        rule_id = parts[3]
        # Extract IPs (simplified)
        alerts.append((timestamp, rule_id, line))

# Find duplicates within 60s
duplicates = 0
for i in range(len(alerts)):
    for j in range(i+1, len(alerts)):
        t1, r1, l1 = alerts[i]
        t2, r2, l2 = alerts[j]
        if r1 == r2 and (t2 - t1).total_seconds() < 60:
            duplicates += 1
            print(f"Duplicate found: {r1} at {t1} and {t2}")

print(f"\nTotal duplicates: {duplicates}")
EOF
```

#### 3. False Positive Rate
```bash
# Manual review required
# Go through app/logs/alerts.log and mark each alert as TP (true positive) or FP (false positive)
# Then calculate: FP_rate = FP / (TP + FP)
```

#### 4. Performance Metrics
```bash
# Memory usage (while IDS running)
ps aux | grep ids_byte_deep.py | awk '{print $6}'  # RSS in KB

# CPU usage
top -p $(pgrep -f ids_byte_deep.py) -bn1 | tail -1 | awk '{print $9}'

# Packet drop rate (from tcpdump stats)
# Requires modification to IDS to output stats
```

---

## Troubleshooting

### Issue 1: Permission Denied
**Symptom**: `Permission denied` khi chạy tcpdump hoặc IDS

**Fix**:
```bash
# Run with sudo
sudo python app/capture_packet/ids_byte_deep.py --iface lo --filter "tcp port 80"

# Or give CAP_NET_RAW capability
sudo setcap cap_net_raw+ep $(which python3)
```

### Issue 2: Interface not found
**Symptom**: `Interface dummy0 does not exist`

**Fix**:
```bash
# Create dummy interface
sudo ip link add dummy0 type dummy
sudo ip link set dummy0 up
sudo ip addr add 192.168.100.1/24 dev dummy0

# Or use loopback
IFACE="lo"
```

### Issue 3: tcpreplay không hoạt động trên loopback
**Symptom**: `tcpreplay` không send packets trên `lo`

**Fix**:
```bash
# Option 1: Use tcpreplay-edit với --loopback
tcpreplay-edit --intf1=lo --loop=1 test.pcap

# Option 2: Use dummy interface thay vì lo
sudo ip link add dummy0 type dummy
sudo ip link set dummy0 up
tcpreplay --intf1=dummy0 test.pcap

# Option 3: Use scapy to replay
python3 <<EOF
from scapy.all import *
pkts = rdpcap("test.pcap")
sendp(pkts, iface="lo", verbose=False)
EOF
```

### Issue 4: No alerts generated
**Symptom**: Replay PCAP nhưng không có alerts

**Debug steps**:
```bash
# 1. Check IDS đang chạy
ps aux | grep ids_byte_deep

# 2. Check IDS đang sniff đúng interface
# Look at IDS output logs

# 3. Check filter có đúng không
# IDS filter: "tcp port 80" - PCAP phải có traffic on port 80

# 4. Manually inspect PCAP
tcpdump -r test.pcap -n | head -20

# 5. Check rules.json có rules match không
grep "UNION" app/capture_packet/rules.json

# 6. Enable verbose mode
python app/capture_packet/ids_byte_deep.py --iface lo --filter "tcp port 80" --verbose

# 7. Check traffic log (should have entries even if no alerts)
tail -f app/logs/traffic.log
```

### Issue 5: Too many alerts (false positives)
**Symptom**: Mỗi test PCAP generate 5-10 alerts thay vì 1

**Possible causes**:
1. Out-of-order segments không được reassemble → mỗi segment trigger alert
2. Retransmissions trigger duplicate alerts
3. Payload logged nhiều lần do duplicate detection fail

**Debug**:
```bash
# Check alert details
cat app/logs/alerts.log

# Look for patterns:
# - Same rule ID, same IPs, different timestamps (< 60s) → duplicate detection fail
# - Same rule ID, same IPs, different payloads → reassembly fail

# Check traffic log for duplicate payloads
grep "hexdump" app/logs/traffic.log | sort | uniq -c | sort -rn | head
```

### Issue 6: IDS crashes or high memory usage
**Symptom**: IDS crashes hoặc memory usage tăng cao

**Debug**:
```bash
# Monitor memory while running
watch -n 1 'ps aux | grep ids_byte_deep | awk "{print \$6}"'

# Check for memory leaks (run for 5 minutes)
# Memory should stabilize after initial ramp-up

# If memory keeps growing → memory leak
# Likely in TCPReassembler or IPDefragmenter (not cleaning up)

# Check connection count
# Add logging to IDS:
# console_logger.info(f"Active TCP connections: {len(self.reasm.conns)}")

# If connection count keeps growing → cleanup not working
```

---

## Next Steps

Sau khi chạy tests:

1. **Analyze results**: Compare expected vs actual alerts
2. **Identify failures**: List test cases failed
3. **Debug failures**: Use troubleshooting guide
4. **Iterate**: Fix bugs, re-run tests
5. **Performance test**: Run với high traffic (1000+ pps)
6. **Document**: Update findings trong PR description

---

## References

- PCAP format: https://wiki.wireshark.org/Development/LibpcapFileFormat
- Scapy documentation: https://scapy.readthedocs.io/
- tcpreplay manual: https://tcpreplay.appneta.com/wiki/
- TCP RFC: https://tools.ietf.org/html/rfc793
