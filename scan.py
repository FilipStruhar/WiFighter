#!venv/bin/python

import os, subprocess, time, scapy, pywifi

interface_name = "wlx502b7330131a"

iface = None
wifi = pywifi.PyWiFi()

for interface in wifi.interfaces():
    if interface_name == interface.name():
            iface = interface

if iface is None:
      print(f"Interface {interface_name} doesnt exist using {wifi.interfaces()[0].name()}...")
      iface = wifi.interfaces()[0]
else:
      print(f"Interface set to {interface_name}")


iface.scan()  # Start scanning
time.sleep(5)  # Wait for scanning to complete

scan_results = iface.scan_results()
ap_list = []

for network in scan_results:
    ap_list.append({
        'SSID': network.ssid,
        'BSSID': network.bssid,
        'Signal': network.signal
    })
    
for ap in ap_list:
    print(f"SSID: {ap['SSID']}, BSSID: {ap['BSSID']}, Signal: {ap['Signal']}")
