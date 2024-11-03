#!venv/bin/python

import os, re, math, time
from prettytable import PrettyTable
from tqdm import tqdm


def scan_wifi(interface):
    scan = None

    # Reset available AP's
    ap_list = []

    # Retrieve raw wifi scan output from iwlist
    estimated_scan_time = 1
    for _ in tqdm(range(estimated_scan_time * 10), desc=f"Scanning for AP's on {interface}", ncols=100):
        if scan is None:
            scan = os.popen(f'iwlist {interface} scan').read()
        time.sleep(0.1)

    # Divide the output into seperate AP sections
    ap_array = scan.split('Cell')

    # Define AP data searching pattern
    essid_pattern = r'ESSID:"([^"]+)"'
    bssid_pattern = r"Address:\s*([0-9A-Fa-f:]+)"
    signal_pattern = r'Signal level=([-+]?\d+)\s*dBm'
    quality_pattern = r'Quality=(\d+)/(\d+)'
    channel_pattern = r'Channel:\s*(\d+)'
    frequency_pattern = r'Frequency:\s*([0-9.]+)\s*GHz'
    encryption_pattern = r'IE:\s*(.*?)(?=\n|$)'
    auth_pattern = r'Authentication Suites \(\d+\)\s*:\s*([^\n]+)'

    skip_first = True

    for ap in ap_array:
        # Skip first element which isn't AP
        if skip_first:
            skip_first = False
            continue
        
        # Find matching data
        bssid_match = re.search(bssid_pattern, ap)
        essid_match = re.search(essid_pattern, ap)
        signal_match = re.search(signal_pattern, ap)
        quality_match = re.search(quality_pattern, ap)
        channel_match = re.search(channel_pattern, ap)
        frequency_match = re.search(frequency_pattern, ap)
        encryption_match = re.findall(encryption_pattern, ap) # Filter "Uknown" entries from array
        encryption_match = [entry.strip() for entry in encryption_match if "Unknown" not in entry]
        auth_match = re.findall(auth_pattern, ap)
        
        # Set AP information
        essid = essid_match.group(1) if essid_match else None
        bssid = bssid_match.group(1) if bssid_match else None
        signal = signal_match.group(1) + ' dBm' if signal_match else None
        quality = quality_match.group(1) + '/70' if quality_match else None
        channel = channel_match.group(1) if channel_match else None

        if frequency_match:
            # Get AP's band from frequency
            frequency = float(frequency_match.group(1))
            frequency_round = math.floor(frequency)
            if frequency_round == 2:
                frequency = "2.4 Ghz"
            elif frequency_round == 5:
                frequency = '5 GHz'
            else:
                frequency = 'Uknown'
        else:
            frequency = None

        if encryption_match:
            wpa3_entry, wpa2_entry, wpa_entry, wep_entry = None, None, None, None
            # Find newest AP's used encryption method
            for entry in encryption_match:
                if "WPA3" in entry:
                    wpa3_entry = entry  # Highest priority
                elif "WPA2" in entry and not wpa3_entry:
                    wpa2_entry = entry  # Next priority if WPA3 is not found
                elif "WPA" in entry and not (wpa3_entry or wpa2_entry):
                    wpa_entry = entry  # Lower priority if neither WPA3 nor WPA2 is found
                elif "WEP" in entry and not (wpa3_entry or wpa2_entry or wpa_entry):
                    wep_entry = entry  # Lowest priority, used only if no WPA standards found
            
            # Set it as a value    
            newest_encryption = wpa3_entry or wpa2_entry or wpa_entry or wep_entry

            # Get the index of the newest encryption
            index = -1
            for entry in encryption_match:
                index += 1
                if newest_encryption in entry: 
                    break
            
            # Get encryption based on the index
            encryption = encryption_match[index]
            # Set encryption method to readable format
            if encryption:
                if "WPA3" in encryption:
                    encryption = "WPA3"
                elif "WPA2" in encryption:
                    encryption = "WPA2"
                elif "WPA" in encryption:
                    encryption = "WPA"
                elif "WEP" in encryption:
                    encryption = "WEP"

            # Get auth based on the index
            if auth_match:
                auth = auth_match[index]
            else:
                auth = None

        # Add AP to available APs array
        ap_list.append({
            'SSID': essid,
            'BSSID': bssid,
            'Channel': channel,
            'Signal': signal,
            'Band': frequency,
            'Encryption': encryption,
            'Auth': auth,
            'Quality': quality
        })

    # Sort array by signal (strongest signal first)
    for ap in ap_list:
        if ap['Signal'] is not None:
            # Remove " dBm" and convert to int
            ap['Signal'] = int(ap['Signal'].replace(" dBm", ""))

    ap_list.sort(key=lambda x: x['Signal'], reverse=True)

    return ap_list


#--------------------------------------#

interface = 'wlp1s0'

try:
    while True:
        ap_list = scan_wifi(interface)

        os.system("clear")

        # Create AP table
        table = PrettyTable()
        table.field_names = ["ID", "SSID", "BSSID", "Channel", "Signal (dBm)", "Band (GHz)", "Encryption", "Auth"]
        ap_index = 0
        for ap in ap_list:
            table.add_row([ap_index ,ap['SSID'], ap['BSSID'], ap['Channel'] , f"{ap['Signal']} dBm", ap['Band'], ap['Encryption'], ap['Auth']])
            ap_index += 1

        # Print AP table
        print("Available Wi-Fi networks:")
        print(table)

        print("\nPress [Ctrl + C] to stop")


except KeyboardInterrupt:
    print(f"\n\nExiting the scan...")


