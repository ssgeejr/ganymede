import pandas as pd
import sys, csv, getopt, mysql.connector
from datetime import datetime
from Astroidbelt import DwarfMoon
from NMAPParser import NMAPEInterpreter

class Parser:
    def __init__(self):
        self.db_connection = None
        self.db_cursor = None
        self.file_path = None
        self.total_hosts = 0
        self.open_ports = 0
        self.parseOnly = False
        self.nmapfile = None

    def connect_to_db(self):
        try:
            dwarfmoon = DwarfMoon('.ganymede')
            self.db_connection = mysql.connector.connect(
                host=dwarfmoon.getServer(),
                user=dwarfmoon.getUsername(),
                password=dwarfmoon.getPassword(),
                database=dwarfmoon.getDB()
            )
            #self.db_cursor = self.db_connection.cursor()
        except mysql.connector.Error as err:
            print("Error connecting to MySQL:", err)
            exit(1)

    def parseNMAPFile(self):
        try:
            print(f'parsing nmap file {self.nmapfile}')
            nmap_parser = NMAPEInterpreter(self.db_connection)
            nmap_parser.parse_file(self.nmapfile, self.parseOnly)
        except FileNotFoundError as e:
            raise FileNotFoundError(f"File Error: {e}")
        except PermissionError as e:
            raise PermissionError(f"File Permission Error: {e}")
        except mysql.connector.Error as e:
            raise mysql.connector.Error(f"Database Error: {e}")
        except Exception as e:
            raise Exception(f"Unexpected Error: {e}")
        finally:
            try:
                if 'conn' in locals() and self.db_connection.is_connected():
                    #cursor.close()
                    self.db_connection.close()
            except NameError:
                pass  # conn wa
                def close_db_connection(self):
                    #if self.db_cursor:
                    #    self.db_cursor.close()
                    if self.db_connection:
                        self.db_connection.close()

    def process(self, argv):

        try:
            opts, args = getopt.getopt(argv, "f:k:hx")
        except getopt.GetoptError as e:
            print('>>>> ERROR: %s' % str(e))
            sys.exit(2)
        for opt, arg in opts:
            if opt == '-h':
                print('Ganymede.py -h Help Message  #This help message')
                print('Ganymede.py -k {nmap file}   #The NMAP file to parse')
                print('Ganymede.py -f {nmap file}   #The NMAP file to parse')
                print('Ganymede.py -x               #DO not insert records ... just print the results')
                sys.exit()
            elif opt in "-x":
                self.parseOnly = True
            elif opt in "-k":
                self.kingdom = arg
            elif opt in "-f":
                self.nmapfile = arg
        
        print(f'Kingdom: {self.kingdom} File {self.nmapfile}')

        if not self.nmapfile or not self.kingdom:
            print('Missing filename or kingdom ...')
            print('python Ganymede.py -k mykingdome -f myfile.nmap')
            sys.exit(-1)
            
        self.parseNMAPFile()


if __name__ == '__main__':
    Parser().process(sys.argv[1:])
