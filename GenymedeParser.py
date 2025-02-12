from scapy.all import rdpcap, IP, TCP, UDP, DNS, DNSQR

def extract_pcap_data(pcap_file):
    packets = rdpcap(pcap_file)  # Load the PCAP file
    host_data = {}

    for pkt in packets:
        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst

            # Store IPs if not already in the dictionary
            if src_ip not in host_data:
                host_data[src_ip] = {'hostname': None, 'open_ports': set()}
            if dst_ip not in host_data:
                host_data[dst_ip] = {'hostname': None, 'open_ports': set()}

            # Extract open ports (TCP/UDP)
            if TCP in pkt and pkt[TCP].dport:
                host_data[src_ip]['open_ports'].add(pkt[TCP].dport)
            if UDP in pkt and pkt[UDP].dport:
                host_data[src_ip]['open_ports'].add(pkt[UDP].dport)

            # Extract hostnames from DNS queries
            if DNS in pkt and pkt.haslayer(DNSQR):
                queried_host = pkt[DNSQR].qname.decode()
                host_data[src_ip]['hostname'] = queried_host

    return host_data

if __name__ == "__main__":
    pcap_file = "testdump.pcap"  # Change this to your PCAP file
    host_data = extract_pcap_data(pcap_file)

    # Print the extracted data
    print("\nExtracted Network Data:")
    print("=" * 40)
    for ip, data in host_data.items():
        hostname = data['hostname'] if data['hostname'] else "N/A"
        open_ports = ", ".join(map(str, data['open_ports'])) if data['open_ports'] else "None"
        print(f"Host IP: {ip}")
        print(f"Hostname: {hostname}")
        print(f"Open Ports: {open_ports}")
        print("-" * 40)
