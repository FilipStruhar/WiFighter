#!/venv/bin/python

import subprocess

def get_wifi_info():
    try:
        # Run the 'nmcli dev wifi list' command and capture the output
        result = subprocess.run(['nmcli', 'dev', 'wifi', 'list'], capture_output=True, text=True, check=True)
        
        # Split the output into lines and ignore the first line (header)
        lines = result.stdout.strip().split('\n')
        header = lines[0]
        data_lines = lines[1:]

        # Find column start positions by the header to correctly parse data
        in_use_idx = header.index('IN-USE')
        bssid_idx = header.index('BSSID')
        ssid_idx = header.index('SSID')
        mode_idx = header.index('MODE')
        chan_idx = header.index('CHAN')
        rate_idx = header.index('RATE')
        signal_idx = header.index('SIGNAL')
        security_idx = header.index('SECURITY')

        # Parse each line and print the AP information
        ap_list = []
        for line in data_lines:
            # Extract each field based on the column indices
            in_use = line[in_use_idx:bssid_idx].strip()
            bssid = line[bssid_idx:ssid_idx].strip()
            ssid = line[ssid_idx:mode_idx].strip()
            mode = line[mode_idx:chan_idx].strip()
            channel = line[chan_idx:rate_idx].strip()
            rate = line[rate_idx:signal_idx].strip()
            signal = line[signal_idx:security_idx].strip()
            security = line[security_idx:].strip()

            # Collect the AP details in a dictionary
            ap_info = {
                'IN-USE': in_use,
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
            print(f"IN-USE: {ap['IN-USE']}, SSID: {ap['SSID']}, BSSID: {ap['BSSID']}, "
                  f"Mode: {ap['Mode']}, Channel: {ap['Channel']}, Rate: {ap['Rate']}, "
                  f"Signal: {ap['Signal']}, Security: {ap['Security']}")

    except subprocess.CalledProcessError as e:
        print(f"Error executing nmcli: {e}")
    except Exception as e:
        print(f"An error occurred: {e}")

# Run the function
get_wifi_info()