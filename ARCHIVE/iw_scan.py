import os, sys, subprocess, time, re
from prettytable import PrettyTable 
from tqdm import tqdm 
from multiprocessing import Process, Pipe


# Archived wifi scan function with tqdm
def scan_ap(interface):
    wifi_networks = []

    scan = None
    estimated_scan_time = 1
    with tqdm(range(estimated_scan_time * 10), desc=f"Scanning for APs on {interface}", ncols=100) as progress_bar:
        for _ in progress_bar:
            if scan is None:
                scan = os.popen(f'iw dev {interface} scan 2>&1').read()
                if 'Device or resource busy' in scan or 'command failed' in scan or 'Network is down' in scan: 
                        print('iw error')
                        progress_bar.close()  # Close the progress bar if the scan fails
                        return
            time.sleep(0.1)
            
    # Divide the output into separate AP sections (split by specific BSS occurrence)
    ap_array = re.split(r"(?=BSS [0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2})", scan)
    
    # Skip first - not AP
    ap_array = ap_array[1:]

    # Define patterns for extracting AP data
    ssid_pattern = r'SSID:\s*(.+)'
    bssid_pattern = r"([0-9A-Fa-f:]{17})"           
    signal_pattern = r"signal: (-?\d+\.\d+) dBm"
    channel_pattern = r"primary channel: (\d+)"
    frequency_pattern = r"freq: (\d+\.\d+)" 
    auth_pattern = r'\* Authentication suites: (.+?)\n'
    cipher_pattern = r'\* Pairwise ciphers: (.+?)\n'

    for ap in ap_array:

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
        signal = f'{round(float(signal_match.group(1)))}' if signal_match else None
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

        # Determine security type
        encryption = None
        if auth and cipher:
            if 'SAE' in auth:
                encryption = 'WPA3'
            elif auth == 'PSK' or auth == 'IEEE 802.1X' and cipher == 'CCMP':
                encryption = 'WPA2'
            elif auth == 'PSK' or auth == 'IEEE 802.1X' and cipher == 'TKIP':
                encryption = 'WPA'
            else:
                encryption = 'WEP' 
        else:
            encryption = "Open/Unknown"

        # Append parsed AP information to array
        wifi_networks.append({
            'SSID': ssid,
            'BSSID': bssid,
            'Channel': channel,
            'Signal': signal,
            'Band': band,
            'Encryption': encryption,
            'Auth': auth,
            'Cipher': cipher
        })
                
    # Sort array by signal strength (strongest first)
    wifi_networks = sorted(wifi_networks, key=lambda x: x['Signal'], reverse=False)

    return wifi_networks