#!venv/bin/python

import os
import re
import time
from prettytable import PrettyTable
from tqdm import tqdm


def scan_wifi(interface):
    scan = None
    ap_list = []

    # Retrieve Wi-Fi scan output from iw
    estimated_scan_time = 3  # Adjust as necessary
    for _ in tqdm(range(estimated_scan_time * 10), desc=f"Scanning for APs on {interface}", ncols=100):
        if scan is None:
            scan = os.popen(f'iw dev {interface} scan').read()
        time.sleep(0.1)


    # Divide the output into separate AP sections
    ap_array = scan.split('BSS')

    # Define patterns for extracting AP data
    ssid_pattern = r'SSID:\s*(.+)'
    bssid_pattern = r"([0-9A-Fa-f:]{17})"           # Matches MAC addresses
    signal_pattern = r"signal: (-?\d+\.\d+) dBm"    # Matches signal strength in dBm
    channel_pattern = r"DS Parameter set: channel (\d+)" # Matches channel number
    frequency_pattern = r"freq: (\d+\.\d+)" 

    auth_pattern = r'\* Authentication suites: (.+?)\n'
    cipher_pattern = r'\* Pairwise ciphers: (.+?)\n'
    

    for ap in ap_array:  # Skip the first split result as it's empty

        if 'signal' in ap:

            ssid_match = re.search(ssid_pattern, ap)
            bssid_match = re.search(bssid_pattern, ap)
            signal_match = re.search(signal_pattern, ap)
            channel_match = re.search(channel_pattern, ap)
            frequency_match = re.search(frequency_pattern, ap)
            auth_match = re.search(auth_pattern, ap)
            cipher_match = re.search(cipher_pattern, ap)
            

            # Extract AP properties or set to None if not found
            ssid = ssid_match.group(1) if ssid_match else None
            bssid = bssid_match.group(1) if bssid_match else None
            signal = f'{round(float(signal_match.group(1)))}' + ' dBm' if signal_match else None
            channel = channel_match.group(1) if channel_match else None
            frequency = round(float(frequency_match.group(1))) if frequency_match else None
            auth = auth_match.group(1) if auth_match else None
            cipher = cipher_match.group(1).strip() if cipher_match else None

            # Map frequency to band (e.g., 2.4 GHz or 5 GHz)
            band = None
            if frequency:
                if frequency < 3000:
                    band = "2.4 GHz"
                elif frequency >= 5000:
                    band = "5 GHz"


            encryption = None
            if auth and cipher:
                if auth == 'PSK SAE':
                    encryption = 'WPA3'
                elif auth == 'PSK' or auth == 'IEEE 802.1X' and cipher == 'CCMP':
                    encryption = 'WPA2'
                elif auth == 'PSK' or auth == 'IEEE 802.1X' and cipher == 'TKIP':
                    encryption = 'WPA'
                else:
                    encryption = 'WEP'
            else:
                encryption = 'Unknown'


            if ssid:
                
                print('\n\n---------------------------------------------\n\n')
                print(ap)
                
                print('#################################')

                print(ssid)
                print(bssid)
                print(channel)
                print(band)
                print(frequency)
                print(encryption)
                print(auth)
                print(cipher)
                

                print('\n\n---------------------------------------------')


            # Append parsed AP information to the list
            """
            ap_list.append({
                'SSID': ssid,
                'BSSID': bssid,
                'Channel': channel,
                'Signal': signal,
                'Band': band,
                'Encryption': encryption,
                'Auth': auth,
                'Cipher': cipher
            })
            """

    # Sort by signal strength (strongest first)
    #ap_list.sort(key=lambda x: x['Signal'] if x['Signal'] is not None else float('-inf'), reverse=True)

    #return ap_list


#--------------------------------------#

interface = 'wlp1s0'
"""
try:
    while True:
        ap_list = scan_wifi(interface)
        os.system("clear")

        # Create AP table
        table = PrettyTable()
        table.field_names = ["ID", "SSID", "BSSID", "Channel", "Signal (dBm)", "Band", "Encryption", "Auth", "Cipher"]
        for idx, ap in enumerate(ap_list):
            table.add_row([
                idx,
                ap['SSID'] or "N/A",
                ap['BSSID'] or "N/A",
                ap['Channel'] or "N/A",
                f"{ap['Signal']} dBm" if ap['Signal'] else "N/A",
                ap['Band'] or "N/A",
                ap['Encryption'],
                ap['Auth'] or "N/A",
                ap['Cipher'] or "N/A"
            ])

        print("Available Wi-Fi networks:")
        print(table)
        print("\nPress [Ctrl + C] to stop")

except KeyboardInterrupt:
    print("\n\nExiting the scan...")
"""

scan_wifi(interface)