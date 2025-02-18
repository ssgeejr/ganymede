# ganymede
PCAP Parser


##  Project Outline 
Having a valid nmap output file, the Ganymede application will parse the file and load it into the database.
This will be used to map the network and show up where it lives and what's listening

For your code -->  ALL you have to do is start coding in the NMAPParser.py file under the process 'def parse_file(self, filename, store_results):'
Everythign else is managed for you, this makes it HIGHLY reusable for processing any type of file format and improves our speed and successrate for multiple files and formats 


Kingdom can only exist once in the kingdom table
Each kingdom will have multiple servers
each server will have multiple ports 

Simple I hope - this should be much easier and faster than a pcap file - we're going to come back to it in teh second half of this program, so don't loose your code. 
We will use the pcap file to map all these servers egress connections 

### Commands and software details

`nmap -p- -A -T4 -sS -sV -sC -O -Pn --min-rate 1000 -oN nmap_scan.txt 192.168.1.0/24`

Explanation:
	sudo → Required for some advanced scanning options.
	nmap → The main command.
	-p- → Scans all 65,535 ports on each host.
	-A → Enables aggressive scan options (OS detection, version detection, script scanning, and traceroute).
	-T4 → Faster scanning (you can lower this if you want a more stealthy scan).
	-sS → SYN scan (stealthier and faster than a full TCP connect scan).
	-sV → Service version detection.
	-sC → Runs default scripts for additional info gathering.
	-O → Attempts OS detection.
	-Pn → Disables host discovery (useful if ICMP is blocked on some hosts).
	--min-rate 1000 → Increases scanning speed by setting a minimum packet rate.
	-oN nmap_scan.txt → Saves the output to a file (nmap_scan.txt).
192.168.1.0/24 → Scans all devices on a typical private local network. Change this based on your actual subnet.
Adjustments:
If you have a different local subnet (e.g., 10.0.0.0/24), modify 192.168.1.0/24 accordingly.
If you don’t want to scan every port, you can replace -p- with -p 1-10000 to scan only the first 10,000 ports.
If the network is large, you might need to adjust timing (-T4 or -T3 for slower but more reliable scans).



Better speed (because the command listed above is deathly slow:
Faster Nmap Command
`nmap -T5 -sS -p- --min-rate=5000 --max-retries=1 --max-scan-delay 0 -oN nmap_scan.txt 192.168.1.0/24`

Optimizations Explained
	-T5 → Insane speed (Fastest scan setting, but may trigger firewall defenses).
	-sS → SYN scan (Faster and stealthier than a full TCP connect scan).
	-p- → Scan all 65,535 ports (Reduce to a range if needed, e.g., -p 1-10000).
	--min-rate=5000 → Sends at least 5000 packets per second (Adjustable based on network).
	--max-retries=1 → Retries failed probes only once (Reduces time wasted on unresponsive hosts).
	--max-scan-delay 0 → Removes artificial delays between probes.
	-oN nmap_scan.txt → Saves the output to a file



##  WORK TO BE DONE 
Some arguments that are required in the application are:

-k {kingdomi}
-f {pcap file}
-x {just run the file, don't load it into the database}

ALL errors should be printed to the screen in the most descriptive setting 
Logging not requried in this release, but will be needed in the 2.0 release

The Kingdom will describe what the pcap file represents. 
For example; 
	`-k guest` might represent the guest network or 
	`-k admin` might represent the administrative network 
	and so forth 
	
The `-f {file}` command just points to a valid pcap file 

`-x` will not execute any database commands 

Parse the file, print the kingdome once
##### Printing to screen 
print every server IP and the hostname if it is available
print every port that is open

##### Pushing to the database
create a new record in the kingdom, get the new kingdom_id
create a new entry in landscape for every IP, use the kingdom_id as the foreign key. Store the hostname if it exists. Get the landscape_id
create a new entry in ports for every open port and protocol (TCP/UDP) using the landscape_id as the foreign key

There is a little more coming down the pipe, but I have to get those items loaded into the database - they are not related to the the work for at this point.
	

### Pull the code download
git clone git@github.com:ssgeejr/ganymede.git -b develop


setup Instructions:

in your home directory, create the folder .ganymede 
then inside of that folder create the file: auth.nfo 

In the auth.nfo add the following details:
```
SERVER~ganymede
DB~ganymededb
USERNAME~jupiters
PASSWORD~icymoon
```

In your hosts file, found in the folder C:\Windows\System32\drivers\etc

Add the following entry at the bottom: 
###.###.###.###	ganymede 

Use the same IP as your ceres entry, the databases are the same - the credentials are different

Install the required tools for parsing files: 

For Linux
```
sudo apt update
sudo apt install tshark -y
usermod -aG wireshark {user}
pip install scapy pyshark mysql-connector-python
#logout / back in to reset permissions
```

For Windows you are going to need "Wireshark" 
```
https://www.wireshark.org/download.html

pip install scapy pyshark mysql-connector-python

```

### List of ALL known ports
`https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml`



## FISHNECK Modules


pip install scapy ipwhois netaddr


-k {kingdomi}
-f {pcap file}
-x {just run the file, don't load it into the database}

ALL errors should be printed to the screen in the most descriptive setting 
Logging not requried in this release, but will be needed in the 2.0 release

The Kingdom will describe what the pcap file represents. 
For example; 
	`-k guest` might represent the guest network or 
	`-k admin` might represent the administrative network 
	and so forth 
	
The `-f {file}` command just points to a valid pcap file 

`-x` will not execute any database commands 

Parse the file, print the kingdome once
##### Printing to screen 
print every server IP and the hostname if it is available
print every port that is open

##### Pushing to the database
create a new record in the kingdom, get the new kingdom_id
create a new entry in landscape for every IP, use the kingdom_id as the foreign key. Store the hostname if it exists. Get the landscape_id
create a new entry in ports for every open port and protocol (TCP/UDP) using the landscape_id as the foreign key

There is a little more coming down the pipe, but I have to get those items loaded into the database - they are not related to the the work for at this point.
	

### Pull the code download
git clone git@github.com:ssgeejr/ganymede.git -b develop


setup Instructions:

in your home directory, create the folder .ganymede 
then inside of that folder create the file: auth.nfo 

In the auth.nfo add the following details:
```
SERVER~ganymede
DB~ganymededb
USERNAME~jupiters
PASSWORD~icymoon
```

In your hosts file, found in the folder C:\Windows\System32\drivers\etc

Add the following entry at the bottom: 
###.###.###.###	ganymede 

Use the same IP as your ceres entry, the databases are the same - the credentials are different

Install the required tools for parsing files: 

For Linux
```
sudo apt update
sudo apt install tshark -y
usermod -aG wireshark {user}
pip install scapy pyshark mysql-connector-python
#logout / back in to reset permissions
```

For Windows you are going to need "Wireshark" 
```
https://www.wireshark.org/download.html

pip install scapy pyshark mysql-connector-python

```

### List of ALL known ports
`https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml`



## FISHNECK Modules


pip install scapy ipwhois netaddr

