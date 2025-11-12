#!/usr/bin/env python3
"""
Generate test PCAP với TCP retransmissions
Test case: HTTP request bình thường với retransmissions
Expected: 0 alerts, không log duplicate cho retransmissions
"""

from scapy.all import Ether, IP, TCP, Raw, wrpcap
import sys
import os

def generate_retransmission_pcap():
    packets = []
    
    # 3-way handshake
    print("[*] Creating 3-way handshake...")
    packets.append(Ether()/IP(src="192.168.1.100", dst="192.168.1.200")/TCP(
        sport=12345, dport=80, flags="S", seq=1000
    ))
    
    packets.append(Ether()/IP(src="192.168.1.200", dst="192.168.1.100")/TCP(
        sport=80, dport=12345, flags="SA", seq=2000, ack=1001
    ))
    
    packets.append(Ether()/IP(src="192.168.1.100", dst="192.168.1.200")/TCP(
        sport=12345, dport=80, flags="A", seq=1001, ack=2001
    ))
    
    # HTTP request - segment 1
    print("[*] Sending HTTP request segment 1...")
    payload1 = b"GET /test HTTP/1.1\r\n"
    packets.append(Ether()/IP(src="192.168.1.100", dst="192.168.1.200")/TCP(
        sport=12345, dport=80, flags="PA", seq=1001, ack=2001
    )/Raw(load=payload1))
    
    # RETRANSMISSION của segment 1 (same seq, same data)
    print("[*] Retransmitting segment 1 (same seq, same data)...")
    packets.append(Ether()/IP(src="192.168.1.100", dst="192.168.1.200")/TCP(
        sport=12345, dport=80, flags="PA", seq=1001, ack=2001
    )/Raw(load=payload1))
    
    # Segment 2
    print("[*] Sending segment 2...")
    payload2 = b"Host: example.com\r\n\r\n"
    packets.append(Ether()/IP(src="192.168.1.100", dst="192.168.1.200")/TCP(
        sport=12345, dport=80, flags="PA", seq=1001+len(payload1), ack=2001
    )/Raw(load=payload2))
    
    # RETRANSMISSION của segment 2
    print("[*] Retransmitting segment 2...")
    packets.append(Ether()/IP(src="192.168.1.100", dst="192.168.1.200")/TCP(
        sport=12345, dport=80, flags="PA", seq=1001+len(payload1), ack=2001
    )/Raw(load=payload2))
    
    # FIN
    print("[*] Closing connection...")
    packets.append(Ether()/IP(src="192.168.1.100", dst="192.168.1.200")/TCP(
        sport=12345, dport=80, flags="FA", seq=1001+len(payload1)+len(payload2), ack=2001
    ))
    
    return packets

def main():
    output_dir = "tests/pcaps"
    output_file = os.path.join(output_dir, "test_retransmission.pcap")
    
    os.makedirs(output_dir, exist_ok=True)
    
    print("=" * 60)
    print("Generating test_retransmission.pcap")
    print("=" * 60)
    
    packets = generate_retransmission_pcap()
    
    print(f"\n[*] Writing {len(packets)} packets to {output_file}...")
    wrpcap(output_file, packets)
    
    print(f"[✓] Created {output_file}")
    print(f"[*] Packet count: {len(packets)}")
    print("\n[*] Test this PCAP with:")
    print(f"    sudo bash tests/scripts/ids_test_workflow.sh lo {output_file}")
    print("\n[*] Expected result: 0 alerts (normal traffic)")
    print("[*] Check logs: should NOT have duplicate entries for retransmissions")

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
