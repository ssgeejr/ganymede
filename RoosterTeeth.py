import argparse
import re
import sqlite3


def parse_nmap_file(nmap_file):
    servers = {}

    with open(nmap_file, 'r', encoding='utf-8') as file:
        lines = file.readlines()

    current_ip = None
    for line in lines:
        ip_match = re.match(r'Nmap scan report for (\d+\.\d+\.\d+\.\d+)', line)
        port_match = re.match(r'(\d+)/\w+\s+open\s+(\S+)', line)

        if ip_match:
            current_ip = ip_match.group(1)
            servers[current_ip] = []

        elif port_match and current_ip:
            port_info = {
                'port': int(port_match.group(1)),
                'service': port_match.group(2)
            }
            servers[current_ip].append(port_info)

    return servers


def insert_data(kingdom, servers, dry_run):
    if dry_run:
        print(f"Kingdom: {kingdom}")
        for ip, ports in servers.items():
            print(f"Server: {ip}")
            for port_info in ports:
                print(f"  Port: {port_info['port']}  Service: {port_info['service']}")
        return

    conn = sqlite3.connect('network_scan.db')
    cursor = conn.cursor()

    cursor.execute("SELECT kingdom_id FROM kingdom WHERE name = ?", (kingdom,))
    result = cursor.fetchone()

    if not result:
        print(f"Error: Kingdom '{kingdom}' not found in the database.")
        return

    kingdom_id = result[0]

    for ip, ports in servers.items():
        cursor.execute("INSERT INTO landscape (kingdom_id, ip) VALUES (?, ?)", (kingdom_id, ip))
        landscape_id = cursor.lastrowid

        for port_info in ports:
            cursor.execute("INSERT INTO ports (landscape_id, port, protocol) VALUES (?, ?, ?)",
                           (landscape_id, port_info['port'], 'TCP'))

    conn.commit()
    conn.close()


def main():
    parser = argparse.ArgumentParser(description='Parse an Nmap scan file and optionally upload to a database.')
    parser.add_argument('-k', required=True, help='Kingdom (grouping of network CIDRs)')
    parser.add_argument('-f', required=True, help='Nmap file to parse')
    parser.add_argument('-x', action='store_true', help='Print results instead of uploading to the database')

    args = parser.parse_args()

    servers = parse_nmap_file(args.f)
    insert_data(args.k, servers, args.x)

    if not args.x:
        print("Data uploaded to the database successfully.")


if __name__ == '__main__':
    main()
