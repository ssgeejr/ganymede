import pandas as pd
import sys, csv, getopt, mysql.connector, socket
from datetime import datetime
import pyshark
from Astroidbelt import DwarfMoon

#testt
class PCAPParser:
    def __init__(self):
        self.db_connection = None
        self.db_cursor = None
        self.file_path = None
        self.total_hosts = 0
        self.open_ports = 0
        self.parseOnly = False
        self.pcapfile = None
        self.kingdom = None

    def connect_to_db(self):
        try:
            dwarfmoon = DwarfMoon('.ganymede')
            self.db_connection = mysql.connector.connect(
                host=dwarfmoon.getServer(),
                user=dwarfmoon.getUsername(),
                password=dwarfmoon.getPassword(),
                database=dwarfmoon.getDB()
            )
            self.db_cursor = self.db_connection.cursor()
        except mysql.connector.Error as err:
            print("Error connecting to MySQL:", err)
            exit(1)

    def parsePCAPFile(self):
        # Dictionaries to hold server info: server_ip -> set(ports)
        servers = {}
        try:
            print(f'Parsing pcap file: {self.pcapfile}')
            capture = pyshark.FileCapture(self.pcapfile)
            for packet in capture:
                # Process only packets that have an IP layer
                if 'IP' not in packet:
                    continue

                # Use destination IP as server IP (adjust if needed)
                server_ip = packet.ip.dst

                # Initialize the set of ports if not seen before
                if server_ip not in servers:
                    servers[server_ip] = set()

                # Check for TCP layer ports
                if 'TCP' in packet:
                    try:
                        # Using source and destination ports; here we assume destination port is "open"
                        port = int(packet.tcp.dstport)
                        servers[server_ip].add(port)
                    except AttributeError:
                        pass  # skip if attribute is missing

                # Check for UDP layer ports
                if 'UDP' in packet:
                    try:
                        port = int(packet.udp.dstport)
                        servers[server_ip].add(port)
                    except AttributeError:
                        pass

            capture.close()
        except Exception as err:
            print(f"Error during PCAP parsing: {err}")
            return

        # Print each server's IP, its hostname (if available) and list of open ports
        print("\n--- Server Information ---")
        for ip, ports in servers.items():
            try:
                # Attempt reverse DNS lookup
                hostname = socket.gethostbyaddr(ip)[0]
            except Exception:
                hostname = "Hostname not available"
            print(f"Server IP: {ip}")
            print(f"Hostname: {hostname}")
            if ports:
                print("Open Ports:")
                for port in sorted(ports):
                    print(f"  - {port}")
            else:
                print("No open ports detected.")
            print("-" * 30)

    def close_db_connection(self):
        if self.db_cursor:
            self.db_cursor.close()
        if self.db_connection:
            self.db_connection.close()

    def process(self, argv):

        try:
            opts, args = getopt.getopt(argv, "f:k:")
        except getopt.GetoptError as e:
            print('>>>> ERROR: %s' % str(e))
            sys.exit(2)
        for opt, arg in opts:
            if opt == '-h':
                print('Ganymede.py -h Help Message')
                print('Ganymede.py -f {pcap file}')
                print('Ganymede.py -k {kingdom}')
                sys.exit()
            elif opt in "-x":
                self.parseOnly = True
            elif opt in "-f":
                self.pcapfile = arg
            elif opt in "-k":
                self.kingdom = arg

        if not self.pcapfile:
            print('Missing filename ...')
            sys.exit(-1)


if __name__ == '__main__':
    parser = PCAPParser()
    parser.process(sys.argv[1:])
    parser.connect_to_db()
    parser.parsePCAPFile()
    parser.close_db_connection()