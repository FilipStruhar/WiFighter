#!venv/bin/python
"""
import subprocess

def get_wifi_info():
    try:
        # Run the 'nmcli dev wifi list' command and capture the output
        result = subprocess.run(['nmcli', 'dev', 'wifi', 'list'], capture_output=True, text=True, check=True)
        
        # Split the output into lines and ignore the first line (header)
        lines = result.stdout.strip().split('\n')[1:]

        # Parse each line and print the AP information
        ap_list = []
        for line in lines:
            # Split line by spaces with a maximum split count to handle spaces in SSIDs
            parts = line.split(maxsplit=7)
            if len(parts) >= 7:
                bssid = parts[0]
                ssid = parts[1]
                mode = parts[2]
                channel = parts[3]
                rate = f"{parts[4]} {parts[5]}"
                signal = parts[6]
                security = parts[7] if len(parts) > 7 else "Unknown"

                # Collect the AP details in a dictionary
                ap_info = {
                    'SSID': ssid,
                    'BSSID': bssid,
                    'Mode': mode,
                    'Channel': channel,
                    'Rate': rate,
                    'Signal': signal,
                    #'Bars': bars,
                    'Security': security
                }

                ap_list.append(ap_info)
        
        # Print the results
        for ap in ap_list:
            print(f"SSID: {ap['SSID']}, BSSID: {ap['BSSID']}, Mode: {ap['Mode']}, "
                  f"Channel: {ap['Channel']}, Rate: {ap['Rate']}, Signal: {ap['Signal']}, "
                  f"Security: {ap['Security']}")

    except subprocess.CalledProcessError as e:
        print(f"Error executing nmcli: {e}")
    except Exception as e:
        print(f"An error occurred: {e}")

# Run the function
get_wifi_info()
"""




#!/venv/bin/python

import subprocess

def get_wifi_info():
    try:
        # Run the 'nmcli dev wifi list' command and capture the output
        result = subprocess.run(['nmcli', 'dev', 'wifi', 'list'], capture_output=True, text=True, check=True)
        
        # Split the output into lines and ignore the first line (header)
        lines = result.stdout.strip().split('\n')[1:]

        # Parse each line and print the AP information
        ap_list = []
        for line in lines:
            parts = line.split()
            
            # Identify columns based on their position from the end of the list
            bssid = parts[0]
            mode = parts[-6]
            channel = parts[-5]
            rate = f"{parts[-4]} {parts[-3]}"
            signal = parts[-2]
            security = parts[-1]

            # SSID is everything between BSSID and Mode
            ssid_parts = parts[1:-(len(parts) - 6)]
            ssid = ' '.join(ssid_parts).strip()

            # Collect the AP details in a dictionary
            ap_info = {
                'SSID': ssid,
                'BSSID': bssid,
                'Mode': mode,
                'Channel': channel,
                'Rate': rate,
                'Signal': signal,
                'Security': security
            }

            ap_list.append(ap_info)

        # Print the results
        for ap in ap_list:
            print(f"SSID: {ap['SSID']}, BSSID: {ap['BSSID']}, Mode: {ap['Mode']}, "
                  f"Channel: {ap['Channel']}, Rate: {ap['Rate']}, Signal: {ap['Signal']}, "
                  f"Security: {ap['Security']}")

    except subprocess.CalledProcessError as e:
        print(f"Error executing nmcli: {e}")
    except Exception as e:
        print(f"An error occurred: {e}")

# Run the function
get_wifi_info()
