#!venv/bin/python

import os, subprocess, time, scapy, pywifi

"""
wifi = pywifi.PyWiFi()
detected_interfaces = []
i = 1

for interface in wifi.interfaces():
    detected_interfaces.append({
        'Name':interface.name(),
        'Interface': interface
    })


for iface in detected_interfaces:
    print(f"{i} - {iface['Name']}")
    i += 1

while True:

    try:
        choice = int(input("\n\nSelect interface: ")) - 1
    except ValueError:
        print("\nInvalid input. Please enter a valid number.")
        continue

    if choice >= 0 and choice < len(detected_interfaces):
        print(f"\nInterface {detected_interfaces[choice]['Name']} chosen")
        break
    else:
        print("\nChoose valid number from list")
"""


wifi = pywifi.PyWiFi()

interface = wifi.interfaces()[0]



try:
    while True:
        
        interface.scan()  # Start scanning
        
        # Get scan results
        scan_results = interface.scan_results()

        ap_list = []

        for network in scan_results:
                ap_list.append({
                    'SSID': network.ssid,
                    'BSSID': network.bssid,
                    'Signal': network.signal,
                    'Band': network.freq,
                    'Auth': network.auth,
                    'Cipher': network.cipher,
                    'AKM': network.akm
                })
        
        # Clear the screen
        os.system("clear")

        # Print the AP list
        print("Available Wi-Fi networks:")
        for ap in ap_list:
                print(f"SSID: {ap['SSID']}, BSSID: {ap['BSSID']}, Signal: {ap['Signal']} dBm, Band: {ap['Band']} MHz, Auth: {ap['Auth']}, Cipher: {ap['Cipher']}, AKM: {ap['AKM']}")


        # Wait before the next scan
        print("\nPress [Ctrl + C] to stop")

        # Refresh rate
        time.sleep(1)
except KeyboardInterrupt:
            print(f"\n\nExiting the scan...")