# WiFighter
Easy-to-use WiFI pen-testing tool for Debian build on aircrack-ng written in python and bash

## Dependecies

```c
apt install -y aircrack-ng hcxdumptool hcxpcapngtool hashcat
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

### 1. Aircrack guide

- WPA, WEP Cracking
- WiFi Scanning
- AP Deauth (DoS)

### Monitor mode

Set interface to monitor
```c
airmon-ng start <INTERFACE>
```

Set interface to managed
```c
airmon-ng stop <INTERFACE>mon
```

### Scan nearby WiFi's

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

### Deauth clients (force handshake)

Deauth all (broadcast)
```c
aireplay-ng -0 1 -a <BSSID> <INTERFACE>mon
```

Deauth client
```c
aireplay-ng -0 1 -a <BSSID> -c <CLIENT_MAC> <INTERFACE>mon
```



### 2. Hcxtools guide - TESTOVAT U TATY, TP-Link OneMesh feature

- PMKID Capture
- Converting raw .pcapng captures to hashcat readable formats

### Installation

```c
git clone https://github.com/ZerBea/hcxtools.git
cd hcxtools
```



### 3. Reaver or Bully ??

- Cracking WPS




