# ganymede
PCAP Parser

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

Use the generated pcap file (check email) and parse the pcap file.
We will want to store the following values in the landscape table (1 per IP), 
    ip VARCHAR(45) NOT NULL,
    hostname VARCHAR(255) NOT NULL DEFAULT 'N/A'
# landscape_id (primary key) is auto-generated,
# and the last_updated timestamp is autoupdated

in the valuetable ports (multiple ports for every landscape entry 0:M)
    landscape_id INT NOT NULL,
    port INT NOT NULL,
    protocol VARCHAR(24) NOT NULL DEFAULT '-',
# The ports primary key (port_id) is auto-generated


