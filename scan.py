#!venv/bin/python

import os, subprocess, time, scapy, pywifi

interface_name = "wlx502b7330131a"

interfaces_arr = []
scan = True
iface = None
wifi = pywifi.PyWiFi()

"""
if iface is None:
      print(f"Interface {interface_name} doesnt exist using {wifi.interfaces()[0].name()}...")
      iface = wifi.interfaces()[0]
else:
      print(f"Interface set to {interface_name}")


try:
    while scan:
        iface.scan()  # Start scanning
        
        # Get scan results
        scan_results = iface.scan_results()
        ap_list = []

        for network in scan_results:
            ap_list.append({
                'SSID': network.ssid,
                'BSSID': network.bssid,
                'Signal': network.signal
            })
        
        # Clear the screen
        os.system("clear")

        # Print the AP list
        print("Available Wi-Fi networks:")
        for ap in ap_list:
            print(f"SSID: {ap['SSID']}, BSSID: {ap['BSSID']}, Signal: {ap['Signal']}")

        #Wait before the next scan
        print("\nPress [Ctrl + C] to stop")
        # Refresh rate
        time.sleep(4)
        
except KeyboardInterrupt:
    print("\nExiting WiFighter...")
"""
