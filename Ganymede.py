import pandas as pd
import sys, csv, getopt, mysql.connector
from datetime import datetime
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
        try:
            print(f'parsing pcap file {self.pcapfile}')
            ###--Insert your code here

        except mysql.connector.Error as err:
            print(f"MySQL Error: {err}")  # Captures MySQL-specific errors

        self.db_connection.commit()
        print(f"New Hosts: {self.total_hosts}")
        print(f"Total Open Ports: {self.open_ports}")

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

        if self.kingdom:
            print(f'Processing kingdom: {self.kingdom}')


if __name__ == '__main__':
    PCAPParser().process(sys.argv[1:])
