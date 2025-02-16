from scapy.all import rdpcap, IP, TCP, UDP
from ipwhois import IPWhois
from netaddr import IPAddress, IPNetwork
import sys

# Define your local subnet (change as needed)
LOCAL_SUBNET = "192.168.1.0/24"


def is_local(ip):
    """Check if an IP belongs to the local subnet."""
    return IPAddress(ip) in IPNetwork(LOCAL_SUBNET)


def extract_servers(pcap_file):
    """Extract local servers and their external communications from a pcap file."""
    packets = rdpcap(pcap_file)
    local_servers = set()
    external_comms = {}

    for pkt in packets:
        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            src_port = pkt[TCP].sport if TCP in pkt else (pkt[UDP].sport if UDP in pkt else None)
            dst_port = pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else None)

            if is_local(src_ip):
                local_servers.add(src_ip)
                if src_ip not in external_comms:
                    external_comms[src_ip] = set()
                if dst_port:
                    external_comms[src_ip].add((dst_ip, dst_port))  # Store remote IP and its listening port

            elif is_local(dst_ip):
                local_servers.add(dst_ip)
                if dst_ip not in external_comms:
                    external_comms[dst_ip] = set()
                if src_port:
                    external_comms[dst_ip].add((src_ip, src_port))  # Store remote IP and its listening port

    return local_servers, external_comms


def whois_lookup(ip):
    """Perform WHOIS lookup on a given IP address."""
    try:
        obj = IPWhois(ip)
        result = obj.lookup_rdap()
        return result.get("asn_description", "Unknown")
    except Exception as e:
        return f"WHOIS lookup failed: {e}"


def main(pcap_file):
    local_servers, external_comms = extract_servers(pcap_file)

    print("\nLocal Servers Found:")
    for server in local_servers:
        print(f" - {server}")

    print("\nExternal Communications:")
    for server, external_ips in external_comms.items():
        print(f"\n{server} communicates with:")
        for ip, port in external_ips:
            if not is_local(ip):
                whois_info = whois_lookup(ip)
                print(f"  - {ip}:{port} ({whois_info})")
            else:
                print(f"  - {ip}:{port} (Local)")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script.py <pcap_file>")
        sys.exit(1)

    pcap_file = sys.argv[1]
    main(pcap_file)
