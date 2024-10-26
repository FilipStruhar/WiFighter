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



"""
from wifi import Cell

import os, time

try:
    while True:
        os.system('clear')

        # Replace 'wlan0' with your Wi-Fi interface name
        networks = Cell.all('wlp1s0')

        # Display network information
        for network in networks:
            print(f"SSID: {network.ssid}")
            print(f"BSSID: {network.address}")
            print(f"Signal: {network.signal} dBm")
            print(f'Quality: {network.quality}')
            print(f"Channel: {network.channel}")
            print(f"Encryption: {network.encryption_type}")
            print(f'Frequency: {network.frequency})')
            print(f'Mode: {network.mode}')
            print("-------------")
        
        time.sleep(6)
except KeyboardInterrupt:
    print('\nExiting...')
"""

