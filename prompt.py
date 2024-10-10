#!venv/bin/python

import os, subprocess, time, scapy, pywifi

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