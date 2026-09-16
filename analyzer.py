from scapy.all import rdpcap, IP, IPv6, TCP, UDP, Raw
from collections import defaultdict
import sys


class NetSecureAnalyzer:

    def __init__(self, filename):
        self.filename = filename
        self.packets = rdpcap(filename)

        self.tcp_connections = defaultdict(list)
        self.udp_connections = defaultdict(int)

        self.syn = 0
        self.syn_ack = 0
        self.ack = 0
        self.rst = 0
        self.fin = 0

        self.retransmissions = 0
        self.tls_client_hello = 0
        self.tls_server_hello = 0
        self.tls_versions = set()

    def get_ip_pair(self, packet):
        if IP in packet:
            return packet[IP].src, packet[IP].dst

        if IPv6 in packet:
            return packet[IPv6].src, packet[IPv6].dst

        return None, None

    def analyze_tcp_flags(self, packet):
        flags = packet[TCP].flags

        if flags & 0x02 and not flags & 0x10:
            self.syn += 1

        if flags & 0x12 == 0x12:
            self.syn_ack += 1

        if flags & 0x10 and not flags & 0x02:
            self.ack += 1

        if flags & 0x04:
            self.rst += 1

        if flags & 0x01:
            self.fin += 1

    def detect_retransmission(self, packet, seen_sequences):
        if TCP not in packet:
            return

        tcp = packet[TCP]
        src, dst = self.get_ip_pair(packet)

        if src is None:
            return

        key = (src, tcp.sport, dst, tcp.dport)

        sequence = tcp.seq
        payload_length = len(bytes(tcp.payload))

        if payload_length == 0:
            return

        previous = seen_sequences[key]

        if sequence in previous:
            self.retransmissions += 1
        else:
            previous.add(sequence)

    def analyze_tls(self, packet):
        if TCP not in packet or Raw not in packet:
            return

        payload = bytes(packet[Raw].load)

        if len(payload) < 6:
            return

        if payload[0] != 0x16:
            return

        if payload[1] != 0x03:
            return

        tls_record_version = payload[1:3]

        if len(payload) < 6:
            return

        handshake_type = payload[5]

        if handshake_type == 0x01:
            self.tls_client_hello += 1

            version = self.extract_client_hello_version(payload)

            if version:
                self.tls_versions.add(version)

        elif handshake_type == 0x02:
            self.tls_server_hello += 1

            version = self.extract_server_hello_version(payload)

            if version:
                self.tls_versions.add(version)

    def extract_client_hello_version(self, payload):
        if len(payload) < 10:
            return None

        version = payload[9:11]

        if version == b"\x03\x03":
            return "TLS 1.2 / TLS 1.3 ClientHello legacy version"

        if version == b"\x03\x02":
            return "TLS 1.1"

        if version == b"\x03\x01":
            return "TLS 1.0"

        return None

    def extract_server_hello_version(self, payload):
        if len(payload) < 7:
            return None

        version = payload[3:5]

        if version == b"\x03\x03":
            return "TLS 1.2 / TLS 1.3"

        if version == b"\x03\x02":
            return "TLS 1.1"

        if version == b"\x03\x01":
            return "TLS 1.0"

        return None

    def analyze(self):
        seen_sequences = defaultdict(set)

        for packet in self.packets:

            if TCP in packet:
                src, dst = self.get_ip_pair(packet)

                key = (
                    src,
                    packet[TCP].sport,
                    dst,
                    packet[TCP].dport
                )

                self.tcp_connections[key].append(packet)

                self.analyze_tcp_flags(packet)

                self.detect_retransmission(
                    packet,
                    seen_sequences
                )

                self.analyze_tls(packet)

            elif UDP in packet:
                src, dst = self.get_ip_pair(packet)

                key = (
                    src,
                    packet[UDP].sport,
                    dst,
                    packet[UDP].dport
                )

                self.udp_connections[key] += 1

    def print_report(self):
        print("\n" + "=" * 60)
        print("              NETSECURE ANALYZER")
        print("=" * 60)

        print("\nPACKET SUMMARY")
        print("-" * 60)
        print(f"Total packets       : {len(self.packets)}")
        print(f"TCP connections     : {len(self.tcp_connections)}")
        print(f"UDP connections     : {len(self.udp_connections)}")

        print("\nTCP ANALYSIS")
        print("-" * 60)
        print(f"SYN packets         : {self.syn}")
        print(f"SYN-ACK packets     : {self.syn_ack}")
        print(f"ACK packets         : {self.ack}")
        print(f"RST packets         : {self.rst}")
        print(f"FIN packets         : {self.fin}")
        print(f"Retransmissions     : {self.retransmissions}")

        if self.syn > 0 and self.syn_ack > 0:
            print("TCP handshake       : SUCCESS")
        elif self.syn > 0:
            print("TCP handshake       : POSSIBLE FAILURE")
        else:
            print("TCP handshake       : NOT DETECTED")

        print("\nTLS ANALYSIS")
        print("-" * 60)
        print(f"ClientHello         : {self.tls_client_hello}")
        print(f"ServerHello         : {self.tls_server_hello}")

        if self.tls_versions:
            for version in self.tls_versions:
                print(f"TLS version         : {version}")
        else:
            print("TLS version         : NOT DETECTED")

        if self.tls_client_hello and self.tls_server_hello:
            print("TLS handshake       : DETECTED")
        elif self.tls_client_hello:
            print("TLS handshake       : INCOMPLETE")
        else:
            print("TLS handshake       : NOT DETECTED")

        self.print_diagnosis()

    def print_diagnosis(self):
        print("\nDIAGNOSIS")
        print("-" * 60)

        issues = []

        if self.syn > 0 and self.syn_ack == 0:
            issues.append(
                "TCP connection establishment may be failing."
            )

        if self.rst > 0:
            issues.append(
                "TCP reset packets detected. "
                "Investigate connection termination."
            )

        if self.retransmissions > 0:
            issues.append(
                f"{self.retransmissions} possible TCP retransmissions "
                "detected. Investigate packet loss, congestion, "
                "or network path issues."
            )

        if self.tls_client_hello > 0 and self.tls_server_hello == 0:
            issues.append(
                "TLS ClientHello detected without a corresponding "
                "ServerHello in the analyzed packets."
            )

        if not issues:
            print(
                "No major TCP/TLS anomaly detected in this capture."
            )
            return

        for number, issue in enumerate(issues, 1):
            print(f"{number}. {issue}")


def main():
    if len(sys.argv) != 2:
        print("Usage: python analyzer.py <capture.pcap>")
        return

    filename = sys.argv[1]

    analyzer = NetSecureAnalyzer(filename)

    analyzer.analyze()
    analyzer.print_report()


if __name__ == "__main__":
    main()