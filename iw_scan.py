#!venv/bin/python

import os, re, math


interface = 'wlp1s0'

scan = os.popen(f'iwlist {interface} scan').read()
ap_array = scan.split('Cell')


skip_first = True

essid_pattern = r'ESSID:"([^"]+)"'
bssid_pattern = r"Address:\s*([0-9A-Fa-f:]+)"
signal_pattern = r'Signal level=([-+]?\d+)\s*dBm'
quality_pattern = r'Quality=(\d+)/(\d+)'
channel_pattern = r'Channel:\s*(\d+)'
frequency_pattern = r'Frequency:\s*([0-9.]+)\s*GHz'
auth_pattern = r'Authentication Suites \(1\)\s*:\s*([^ \n]+)'
encryption_pattern = r'IE:\s*(.*?)(?=\n|$)'


for ap in ap_array:
    if skip_first:
        skip_first = False
        continue

    bssid_match = re.search(bssid_pattern, ap)
    essid_match = re.search(essid_pattern, ap)
    signal_match = re.search(signal_pattern, ap)
    quality_match = re.search(quality_pattern, ap)
    channel_match = re.search(channel_pattern, ap)
    frequency_match = re.search(frequency_pattern, ap)
    auth_match = re.findall(auth_pattern, ap)
    encryption_match = re.findall(encryption_pattern, ap)
    # Filter "Uknown" entries from array
    encryption_match = [entry.strip() for entry in encryption_match if "Unknown" not in entry]
    
    if essid_match:
        essid = essid_match.group(1)
    else:
       essid = None
    if bssid_match:
        bssid = bssid_match.group(1)
    else:
        bssid = None
    if signal_match:
        signal = signal_match.group(1) + ' dBm'
    else:
        signal = None
    if quality_match:
        quality = quality_match.group(1) + '/70'
    else:
        quality = None
    if channel_match:
        channel = channel_match.group(1)
    else:
        channel = None
    if frequency_match:
        frequency = float(frequency_match.group(1))
        frequency_round = math.floor(frequency)
        if frequency_round == 2:
            frequency = "2.4 Ghz"
        elif frequency_round == 5:
            frequency = '5 GHz'
        else:
            frequency = None
    else:
        frequency = None
    if auth_match:
        auth = auth_match[-1]
    else:
        auth = None
    if encryption_match:
        encryption = encryption_match[-1]
    else:
        encryption = None

    print('\n\n')
    print('------------------------------------------------')
    print(essid)

    for au in auth_match:
        print(au)

    print('=====')

    for enc in encryption_match:
        print(enc)
       
    print('------------------------------------------------')
    """
    print('\n\n')
    print('------------------------------------------------')
    print(essid)
    print(bssid)
    print(signal)
    print(quality)
    print(f'Channel: {channel}')
    print(frequency)
    print(auth)
    print(encryption)
    print('------------------------------------------------')
    """