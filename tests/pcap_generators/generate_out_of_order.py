#!/usr/bin/env python3
"""
Generate test PCAP với out-of-order TCP segments
Test case: HTTP request với SQLi payload, segments gửi không theo thứ tự
Expected: 1 alert khi reassemble xong (không phải nhiều alerts)
"""

from scapy.all import Ether, IP, TCP, Raw, wrpcap
import sys
import os

def generate_out_of_order_pcap():
    packets = []
    
    # 3-way handshake
    print("[*] Creating 3-way handshake...")
    p1 = Ether()/IP(src="192.168.1.100", dst="192.168.1.200")/TCP(
        sport=12345, dport=80, flags="S", seq=1000
    )
    packets.append(p1)
    
    p2 = Ether()/IP(src="192.168.1.200", dst="192.168.1.100")/TCP(
        sport=80, dport=12345, flags="SA", seq=2000, ack=1001
    )
    packets.append(p2)
    
    p3 = Ether()/IP(src="192.168.1.100", dst="192.168.1.200")/TCP(
        sport=12345, dport=80, flags="A", seq=1001, ack=2001
    )
    packets.append(p3)
    
    # HTTP request với SQLi - split thành 5 segments
    print("[*] Creating HTTP request with SQLi payload...")
    payload = b"GET /admin?id=1' UNION SELECT * FROM users-- HTTP/1.1\r\nHost: example.com\r\n\r\n"
    
    # Split payload into 5 segments
    seg1 = payload[0:20]   # "GET /admin?id=1' UNI"
    seg2 = payload[20:40]  # "ON SELECT * FROM use"
    seg3 = payload[40:60]  # "rs-- HTTP/1.1\r\nHost:"
    seg4 = payload[60:80]  # " example.com\r\n\r\n"
    seg5 = payload[80:] if len(payload) > 80 else b""    # (remaining)
    
    print(f"  Segment 1 (seq=1001): {seg1}")
    print(f"  Segment 2 (seq=1021): {seg2}")
    print(f"  Segment 3 (seq=1041): {seg3}")
    print(f"  Segment 4 (seq=1061): {seg4}")
    if seg5:
        print(f"  Segment 5 (seq=1081): {seg5}")
    
    # Send segments OUT OF ORDER: 1, 3, 5, 2, 4
    print("[*] Sending segments out of order: 1, 3, 5, 2, 4")
    
    # Segment 1 (seq=1001) - IN ORDER
    p4 = Ether()/IP(src="192.168.1.100", dst="192.168.1.200")/TCP(
        sport=12345, dport=80, flags="PA", seq=1001, ack=2001
    )/Raw(load=seg1)
    packets.append(p4)
    
    # Segment 3 (seq=1041) - OUT OF ORDER (skip segment 2)
    p5 = Ether()/IP(src="192.168.1.100", dst="192.168.1.200")/TCP(
        sport=12345, dport=80, flags="PA", seq=1041, ack=2001
    )/Raw(load=seg3)
    packets.append(p5)
    
    # Segment 5 (seq=1081) - OUT OF ORDER (if exists)
    if seg5:
        p6 = Ether()/IP(src="192.168.1.100", dst="192.168.1.200")/TCP(
            sport=12345, dport=80, flags="PA", seq=1081, ack=2001
        )/Raw(load=seg5)
        packets.append(p6)
    
    # Segment 2 (seq=1021) - MISSING SEGMENT arrives
    p7 = Ether()/IP(src="192.168.1.100", dst="192.168.1.200")/TCP(
        sport=12345, dport=80, flags="PA", seq=1021, ack=2001
    )/Raw(load=seg2)
    packets.append(p7)
    
    # Segment 4 (seq=1061)
    p8 = Ether()/IP(src="192.168.1.100", dst="192.168.1.200")/TCP(
        sport=12345, dport=80, flags="PA", seq=1061, ack=2001
    )/Raw(load=seg4)
    packets.append(p8)
    
    # FIN
    print("[*] Closing connection with FIN...")
    final_seq = 1001 + len(payload)
    p9 = Ether()/IP(src="192.168.1.100", dst="192.168.1.200")/TCP(
        sport=12345, dport=80, flags="FA", seq=final_seq, ack=2001
    )
    packets.append(p9)
    
    return packets

def main():
    output_dir = "tests/pcaps"
    output_file = os.path.join(output_dir, "test_out_of_order.pcap")
    
    # Create output directory if not exists
    os.makedirs(output_dir, exist_ok=True)
    
    print("=" * 60)
    print("Generating test_out_of_order.pcap")
    print("=" * 60)
    
    packets = generate_out_of_order_pcap()
    
    print(f"\n[*] Writing {len(packets)} packets to {output_file}...")
    wrpcap(output_file, packets)
    
    print(f"[✓] Created {output_file}")
    print(f"[*] Packet count: {len(packets)}")
    print("\n[*] Test this PCAP with:")
    print(f"    sudo bash tests/scripts/ids_test_workflow.sh lo {output_file}")
    print("\n[*] Expected result: 1 alert for SQLi (UNION SELECT)")

if __name__ == "__main__":
    try:
        main()
    except ImportError as e:
        print(f"[ERROR] Missing dependency: {e}")
        print("[*] Install with: pip install scapy")
        sys.exit(1)
    except Exception as e:
        print(f"[ERROR] {e}")
        sys.exit(1)
