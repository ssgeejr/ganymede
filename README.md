# ganymede
PCAP Parser


##  WORK TO BE DONE 
Here is the overall goal of the application ... 
Having a valid pcap file, the Ganymede application will parese the file and load it into the database. 
This will be used to map the network. 
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

