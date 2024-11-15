#!venv/bin/python

# | IMPORT | #

import os, sys, subprocess, time, re
from prettytable import PrettyTable
from tqdm import tqdm

# | GRAPHICS | #

# Colors
RED = '\033[31m'
ORANGE = '\033[38;5;214m'
GREEN = '\033[32m'
YELLOW = '\033[33m'
BLUE = '\033[34m'
MAGENTA = '\033[35m'
CYAN = '\033[36m'
RESET = '\033[0m'

# Logo
LOGO = r"""
 __      __._____________.__       .__     __                
/  \    /  \__\_   _____/|__| ____ |  |___/  |_  ___________ 
\   \/\/   /  ||    __)  |  |/ ___\|  |  \   __\/ __ \_  __ )
 \        /|  ||     \   |  / /_/  >   Y  \  | \  ___/|  | \/
  \__/\  / |__|\___  /   |__\___  /|___|  /__|  \___  >__|   
       \/          \/      /_____/      \/          \/                                                                           
"""


 #------------------------------------------------------------------------------------

# | VARIABLES | #

ap_list = []
interface = None
target_ap = None


 #------------------------------------------------------------------------------------

 # | INTRODUCTION | #

def introduction():
     os.system("clear")

     # | INTRODUCTION | #

     # Show logo
     print(f"{ORANGE}{LOGO}{RESET}")
     print()
     print(f"{ORANGE}Welcome :D This is WiFighter!{RESET}")
     print(f"{ORANGE}Easy-to-use WiFi pen-testing security tool{RESET}")
     #print(" ")
     #print(f"{MAGENTA}Build by Filip Struhar | https://github.com/FilipStruhar{RESET}")
     #print()
     #print(f'{ORANGE}____________________________________________{RESET}')

     print()
     print()

#---------------------------------

 # | MONITOR MODE | #

def start_service(service):
     status = os.popen(f'systemctl is-active {service}').read().strip()

     if status == 'inactive':
          print(f"{ORANGE}Starting {service}...{RESET}")
          os.system(f'systemctl start {service}')
     else:
          print(f"{ORANGE}{service} is already running.{RESET}")

def stop_service(service):
     status = os.popen(f'systemctl is-active {service}').read().strip()

     if status == 'active':
          print(f"{ORANGE}Stopping {service}...{RESET}")
          os.system(f'systemctl stop {service}')
     else:
          print(f"{ORANGE}{service} is not running.{RESET}")


def interface_mode(interface):
     mode = None

     output = os.popen(f'sudo iwconfig {interface} 2>/dev/null').read()
     for line in output.splitlines():
          if 'Mode' in line:
               if 'Managed' in line:
                    mode = 'Managed'
               elif 'Monitor' in line:
                    mode = 'Monitor'
               break
     return mode


def monitor_switch(command, interface):
     interfering_services = ['NetworkManager', 'wpa_supplicant']
     mode = interface_mode(interface)

     if mode:
          # Start Monitor mode
          if command == "start" and mode == "Managed":
               # Kill interfering services
               for service in interfering_services:
                    stop_service(service)

               # Switch interface to Monitor
               os.system(f'ifconfig {interface} down')
               print(f"{ORANGE}\nSetting {interface} to monitor mode...{RESET}")
               os.system(f'iwconfig {interface} mode monitor')
               os.system(f'ifconfig {interface} up')

          elif command == "start":
               print(f'{ORANGE}Interface {interface} is already in Monitor Mode, skipping...\n{RESET}')
          
          # Stop Monitor mode
          if command == "stop" and mode == "Monitor":
               # Switch interface to Managed
               os.system(f'ifconfig {interface} down')
               print(f"{ORANGE}\nSetting {interface} to managed mode...{RESET}")
               os.system(f'iwconfig {interface} mode managed')
               os.system(f'ifconfig {interface} up')

               # Start needed services
               for service in interfering_services:
                    start_service(service)
          elif command == "stop":
               print(f'{ORANGE}Interface {interface} is already in Managed Mode, skipping...\n{RESET}')              
     else:
          print(f'{RED}Interface "{interface}" does not exist! Retype "wifigter [start/stop/status] [-INTERFACE_NAME-]"\n{RESET}')

#---------------------------------

 # | CHOOSING | #

def choose_interface():
     interfaces_path = '/sys/class/net/'
     detected_interfaces = []

    # Iterate over all the interfaces in the directory
     for interface in os.listdir(interfaces_path):
          # Make sure that the interface is a wireless interface
          if os.path.exists(os.path.join(interfaces_path, interface, 'wireless')):
               detected_interfaces.append(interface)

     idx = 1
     # Show detected interfaces
     print("Available Wi-Fi Interfaces:")
     for interface in detected_interfaces:
          print(f"{CYAN}{idx}. {interface}{RESET}")
          idx += 1

     try:
          while True:     
               try:
                    # Prompt the user to choose an interface by number
                    choice = int(input(f"\n{CYAN}Select the interface number:{RESET} ")) - 1
               except ValueError:
                    print(f"{RED}Invalid input! Please enter a valid number.{RESET}")
                    continue
               
               # Check if the choice is in range
               if 0 <= choice < len(detected_interfaces):
                    # Return chosen interface
                    interface = detected_interfaces[choice]
                    return interface
               else:
                    print(f"{RED}Invalid choice! Please select a valid number from the list.{RESET}")
     except:
          print(f"\n\n{ORANGE}Exiting the tool...{RESET}")

     
def choose_target():
     global ap_list

     try:
          while True:     
               # Prompt the user to choose an interface by number
               try:
                    # Prompt the user to choose an interface by number
                    choice = int(input(f"\n{CYAN}Select the interface number:{RESET} "))
               except ValueError:
                    print(f"{RED}Invalid input! Please enter a valid number.{RESET}")
                    continue
               # Check if the choice is in range
               if 0 <= choice < len(ap_list):
                    # Return chosen interface
                    target_ap = ap_list[choice]
                    return target_ap
               else:
                    print(f"{RED}Invalid choice! Please select a valid number from the list.{RESET}")
     except:
          print(f"\n\n{ORANGE}Exiting the tool...{RESET}")


 #------------------------------------------------------------------------------------

# | Wifi Scan | #

def wifi_list(interface):
     scan = None
     ap_list = []

     # Retrieve Wi-Fi scan output from iw
     estimated_scan_time = 1
     for _ in tqdm(range(estimated_scan_time * 10), desc=f"Scanning for APs on {interface}", ncols=100):
          if scan is None:
               scan = os.popen(f'iw dev {interface} scan').read()
          time.sleep(0.1)

     # Divide the output into separate AP sections (split by specific BSS occurrence)
     ap_array = re.split(r"(?=BSS [0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2})", scan)
     # Skip first - not AP
     ap_array = ap_array[1:]

     # Define patterns for extracting AP data
     ssid_pattern = r'SSID:\s*(.+)'
     bssid_pattern = r"([0-9A-Fa-f:]{17})"           
     signal_pattern = r"signal: (-?\d+\.\d+) dBm"
     channel_pattern = r"DS Parameter set: channel (\d+)" 
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
               if auth == 'PSK SAE':
                    encryption = 'WPA3'
               elif auth == 'PSK' or auth == 'IEEE 802.1X' and cipher == 'CCMP':
                    encryption = 'WPA2'
               elif auth == 'PSK' or auth == 'IEEE 802.1X' and cipher == 'TKIP':
                    encryption = 'WPA'
               else:
                    encryption = 'WEP'  
          # Append parsed AP information
          #  to the list
          #if int(signal) > -100:
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
                    
     # Sort by signal strength (strongest first)
     ap_list = sorted(ap_list, key=lambda x: x['Signal'], reverse=False)

     return ap_list

 #------------------------------------------------------------------------------------

# | CODE | #

# Try catching monitor switch command
try:
     command = sys.argv[1]
except:
     command = None

if command:
     # Check if command has all needed arguments
     if len(sys.argv) == 3:
          interface = sys.argv[2]

          if command == "start" or command == "stop":
               # Call monitor switch function
               monitor_switch(command, interface)
          elif command == "status":
               # Show interface mode status
               mode = interface_mode(interface)
               if mode:
                    print(f'{ORANGE}Interface {interface} is {mode}\n{RESET}')
               else:
                    print(f'{RED}Interface "{interface}" does not exist! Type "wifigter [start/stop/status] [-INTERFACE_NAME-]"\n{RESET}')
          else:
               print(f'{RED}Invalid Command! Type "wifigter [start/stop/status] [-INTERFACE_NAME-]"\n{RESET}')
     else:
          print(f'{RED}Invalid Command! Type "wifigter [start/stop/status] [-INTERFACE_NAME-]"\n{RESET}')
else:

     # Show logo
     introduction()

     # Let the user choose scanning/attacking interface
     interface = choose_interface()

     if interface:
          try:
               while True:
                    ap_list = wifi_list(interface)
                    os.system("clear")

                    introduction()

                    # Create AP table
                    table = PrettyTable()
                    table.field_names = ["ID", "SSID", "BSSID", "Channel", "Signal (dBm)", "Band", "Encryption", "Auth", "Cipher"]
                    for idx, ap in enumerate(ap_list):
                         table.add_row([
                              f"{CYAN}{idx}{RESET}",
                              ap['SSID'] or "N/A",
                              ap['BSSID'] or "N/A",
                              ap['Channel'] or "N/A",
                              f"{ap['Signal']} dBm" if ap['Signal'] else "N/A",
                              ap['Band'] or "N/A",
                              ap['Encryption'] or "Open/Unknown",
                              ap['Auth'] or "N/A",
                              ap['Cipher'] or "N/A"
                         ])

                    print("Available Wi-Fi networks:")
                    print(table)
                    print("\nPress [Ctrl + C] to stop")

                    time.sleep(1)

          except KeyboardInterrupt:
               if ap_list:
                    target_ap = choose_target()
                    print(target_ap)
               else:
                    print(f"{RED}No AP's found, exiting...{RESET}\n")

     
