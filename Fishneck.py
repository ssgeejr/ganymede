import argparse
import socket
from scapy.all import rdpcap, IP, TCP, UDP
from ipwhois import IPWhois
from netaddr import IPAddress, IPNetwork
from collections import defaultdict

# Default subnet (can be overridden with -s argument)
DEFAULT_LOCAL_SUBNET = "192.168.0.0/16"

def get_local_ip():
    """Retrieve the IP address of the machine running the script."""
    try:
        return socket.gethostbyname(socket.gethostname())
    except:
        return None

def is_local(ip, local_subnet):
    """Check if an IP belongs to the user-specified local subnet."""
    return IPAddress(ip) in IPNetwork(local_subnet)

def extract_servers_and_ports(pcap_file, local_subnet, scan_ports=True):
    """Extract local servers, open ports (if enabled), and external communications from a pcap file."""
    packets = rdpcap(pcap_file)
    local_servers = set()
    external_comms = defaultdict(set)
    open_ports = defaultdict(set) if scan_ports else None  # Only track ports if scanning is enabled
    scanning_host_ip = get_local_ip()

    for pkt in packets:
        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            src_port = pkt[TCP].sport if TCP in pkt else (pkt[UDP].sport if UDP in pkt else None)
            dst_port = pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else None)

            # Ignore the scanning host
            if src_ip == scanning_host_ip or dst_ip == scanning_host_ip:
                continue

            # Identify local servers
            if is_local(src_ip, local_subnet):
                local_servers.add(src_ip)
                if scan_ports and TCP in pkt and pkt[TCP].flags == 0x12:  # SYN-ACK means open port
                    open_ports[src_ip].add(src_port)
                if dst_port:
                    external_comms[src_ip].add((dst_ip, dst_port))

            elif is_local(dst_ip, local_subnet):
                local_servers.add(dst_ip)
                if scan_ports and src_port:
                    open_ports[dst_ip].add(dst_port)
                if src_port:
                    external_comms[dst_ip].add((src_ip, src_port))

    return local_servers, external_comms, open_ports

def whois_lookup(ip):
    """Perform WHOIS lookup on a given IP address."""
    try:
        obj = IPWhois(ip)
        result = obj.lookup_rdap()
        return result.get("asn_description", "Unknown")
    except Exception:
        return "WHOIS lookup failed"

def generate_report(local_servers, external_comms, open_ports, local_subnet, scan_ports=True, do_whois=True):
    """Generate the final report."""
    output = []

    output.append("\nLocal Servers Found:")
    for server in local_servers:
        open_ports_str = f"(Open Ports: {', '.join(map(str, sorted(open_ports[server])))} )" if scan_ports and open_ports[server] else "(No open ports scanned)"
        output.append(f" - {server} {open_ports_str}")

    output.append("\nExternal Communications:")
    for server, external_ips in external_comms.items():
        output.append(f"\n{server} communicates with:")
        for ip, port in external_ips:
            if do_whois and not is_local(ip, local_subnet):  # FIXED: Using local_subnet, not DEFAULT_LOCAL_SUBNET
                whois_info = whois_lookup(ip)
                output.append(f"  - {ip}:{port} ({whois_info})")
            else:
                output.append(f"  - {ip}:{port} (Local)")

    return "\n".join(output)

def main():
    parser = argparse.ArgumentParser(description="Analyze a pcap file to extract local servers, open ports, and external communications.")
    parser.add_argument("pcap_file", help="Path to the pcap file")
    parser.add_argument("-s", "--subnet", default=DEFAULT_LOCAL_SUBNET, help="Specify the local subnet (default: 192.168.0.0/16)")
    parser.add_argument("-p", "--no-port-scan", action="store_true", help="Disable scanning for open ports")
    parser.add_argument("-w", "--no-whois", action="store_true", help="Disable WHOIS lookup for external IPs")
    parser.add_argument("-o", "--output", help="Write the output to a specified file")

    args = parser.parse_args()
    local_subnet = args.subnet
    scan_ports = not args.no_port_scan
    do_whois = not args.no_whois
    output_file = args.output

    # Process pcap file
    local_servers, external_comms, open_ports = extract_servers_and_ports(args.pcap_file, local_subnet, scan_ports)

    # Generate report
    report = generate_report(local_servers, external_comms, open_ports, local_subnet, scan_ports, do_whois)

    # Output to file or console
    if output_file:
        with open(output_file, "w") as f:
            f.write(report)
        print(f"Output written to {output_file}")
    else:
        print(report)

if __name__ == "__main__":
    main()
