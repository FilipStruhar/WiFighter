# WiFighter
Easy-to-use WiFI pen-testing/scanning tool written in python



## Installation 

**Dependencies**
```c
sudo apt install python3 python3-venv python3-pip hashcat ...
```

**Creating python virtual enviroment**

Clone the project
```c
git clone https://github.com/FilipStruhar/WiFighter.git
```

Enter the project folder
```c
cd WiFighter
```

Create virtual enviroment
```c
python3 -m venv venv
```

Enter the virtual enviroment
```c
source venv/bin/activate
```

Install python modules (scapy, pywifi) 
```c
pip install -r requirements.txt
```

Exit from virtual enviroment
```c
deactivate
```


## WiFi Scan & Select
```python
  import pywifi, scapy
```



## Threat Hunt
```python
  import pywifi, scapy
```



## Attack mode

### 1. WPA/WPA2 Handshake Crack

**Aircrack guide**
- WPA, WEP Cracking
- WiFi Scanning
- AP Deauth (DoS)

**Monitor mode**

Set interface to monitor
```c
airmon-ng start <INTERFACE>
```

Set interface to managed
```c
airmon-ng stop <INTERFACE>mon
```

**Scan nearby WiFi's**

Scan all
```c
airodump-ng <INTERFACE>mon
```

Scan 2.4GHz WiFi's
```c
airodump-ng --band gb <ESSID> <INTERFACE>mon
```

Scan 5GHz WiFi's
```c
airodump-ng --band a <ESSID> <INTERFACE>mon
```

Listen for handshake of specified AP
```c
airodump-ng -c <CHANNEL> -b <BSSID> -w OUTPUT_PATH <INTERFACE>mon
```

**Deauth clients (force handshake)**

Deauth all (broadcast)
```c
aireplay-ng -0 1 -a <BSSID> <INTERFACE>mon
```

Deauth client
```c
aireplay-ng -0 1 -a <BSSID> -c <CLIENT_MAC> <INTERFACE>mon
```



### 2. PMKID Attack (802.11r exploit)

**Hcxtools guide - TESTOVAT U TATY, TP-Link OneMesh feature**

- PMKID Capture
- Converting raw .pcapng captures to hashcat readable formats

**Installation**

```c
git clone https://github.com/ZerBea/hcxtools.git
cd hcxtools
```



### 3. WPS

**Reaver or Bully ??**
- Online WPS PIN Brute Force

**Pixie Dust**
- Offline WPS PIN crack
- Není to brute force (rychlejší)
- Využívá slabé kryptografie PINu (né každý router je náchyloý)




