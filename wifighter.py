#!venv/bin/python

# | IMPORT | #

import os, sys, subprocess, time, re
from prettytable import PrettyTable 
from tqdm import tqdm 
from multiprocessing import Process, Pipe


# | GRAPHICS | #

ORANGE = '\033[38;5;214m' # Main color
YELLOW = '\033[33m' # System action
RED = '\033[31m' # Error
GREEN = '\033[32m' # Correct
BLUE = '\033[34m'
MAGENTA = '\033[35m'
CYAN = '\033[36m'
RESET = '\033[0m' # Reset color

LOGO = r"""
 __      __._____________.__       .__     __                
/  \    /  \__\_   _____/|__| ____ |  |___/  |_  ___________ 
\   \/\/   /  ||    __)  |  |/ ___\|  |  \   __\/ __ \_  __ )
 \        /|  ||     \   |  / /_/  >   Y  \  | \  ___/|  | \/
  \__/\  / |__|\___  /   |__\___  /|___|  /__|  \___  >__|   
       \/          \/      /_____/      \/          \/                                                                           
"""


 #------------------------------------------------------------------------------------

# | GLOBAL VARIABLES | #

interfering_services = ['NetworkManager', 'wpa_supplicant']
wifi_networks = []
interface = None
target_ap = None

 #------------------------------------------------------------------------------------

 # | INTRODUCTION | #

def introduction():

     # | INTRODUCTION | #

     os.system('clear')
     # Show logo
     print(f"{BLUE}{LOGO}{RESET}")
     print()
     print(f"{BLUE}Welcome :D This is WiFighter!{RESET}")
     print(f"{BLUE}Easy-to-use WiFi pen-testing security tool{RESET}")
     #print(" ")
     #print(f"{MAGENTA}Build by Filip Struhar | https://github.com/FilipStruhar{RESET}")

     print()
     print()

#---------------------------------

 # | MONITOR MODE | #

def start_services(verbose):
     global interfering_services
     for service in interfering_services:
          status = os.popen(f'systemctl is-active {service}').read().strip()

          if status == 'inactive':
               if verbose:
                    print(f"{CYAN}Starting {service} service...{RESET}")
               os.system(f'systemctl start {service}')
          else:
               if verbose:
                    print(f"{CYAN}{service} service is already running.{RESET}")

def stop_services(verbose):
     global interfering_services
     for service in interfering_services:
          status = os.popen(f'systemctl is-active {service}').read().strip()

          if status == 'active':
               if verbose:
                    print(f"{CYAN}Stopping {service} service...{RESET}")
               os.system(f'systemctl stop {service}')
          else:
               if verbose:
                    print(f"{CYAN}{service} service is not running.{RESET}")


def interface_mode(interface):
     mode = None
     interface_info = os.popen(f'iw dev {interface} info').read()
     if 'type managed' in interface_info:
          mode = 'Managed'
     elif 'type monitor' in interface_info:
          mode = 'Monitor'

     return mode


def monitor_switch(verbose, command, interface):
     mode = interface_mode(interface)

     if mode:
          # Start Monitor mode
          if command == "start" and mode == "Managed":
               # Kill interfering services
               stop_services('verbose')

               # Switch interface to Monitorw
               os.system(f'ip link set {interface} down')
               if verbose:
                    print(f"{CYAN}\nSetting {interface} to monitor mode...{RESET}")
               os.system(f'iw dev {interface} set type monitor')
               os.system(f'ip link set {interface} up')
          elif command == "start":
               if verbose:
                print(f'{CYAN}Interface {interface} is already in Monitor Mode, skipping...\n{RESET}')
          
          # Stop Monitor mode
          if command == "stop" and mode == "Monitor":
               # Switch interface to Managed
               os.system(f'ip link set {interface} down')
               if verbose:
                    print(f"{CYAN}\nSetting {interface} to managed mode...{RESET}")
               os.system(f'iw dev {interface} set type managed')
               os.system(f'ip link set {interface} up')

               # Start needed services
               start_services('verbose')

          elif command == "stop":
               if verbose:
                print(f'{CYAN}Interface {interface} is already in Managed Mode, skipping...\n{RESET}')              
     else:
          if verbose:
           print(f'{RED}Interface "{interface}" does not exist! Retype "wifighter [start/stop/status] [-INTERFACE_NAME-]"\n{RESET}')


def list_interfaces():
     interfaces_path = '/sys/class/net/'
     print(f"{CYAN}Detected Wi-Fi Interfaces:{RESET}")
     print()
    # Iterate over all the interfaces in the directory
     for interface in os.listdir(interfaces_path):
          # Make sure that the interface is a wireless interface
          if os.path.exists(os.path.join(interfaces_path, interface, 'wireless')):
               print(f"{CYAN}{interface}{RESET}")

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
     print("Select Wi-Fi Interface:")
     for interface in detected_interfaces:
          print(f"{idx}. {interface}")
          idx += 1
     try:
          while True:     
               try:
                    # Prompt the user to choose an interface by number
                    choice = int(input(f"\nInterface number: ")) - 1
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
     except KeyboardInterrupt:
          print(f"\n\n{BLUE}Exiting the tool...{RESET}")

     
def choose_target():
     global wifi_networks

     try:
          while True:     
               try:
                    # Prompt the user to choose an interface by number
                    choice = int(input(f"\nSelect the interface number: "))
               except ValueError:
                    print(f"{RED}Invalid input! Please enter a valid number.{RESET}")
                    continue
               # Check if the choice is in range
               if 0 <= choice < len(wifi_networks):
                    target_ap = wifi_networks[choice]
                    return target_ap # Return chosen interface
               else:
                    print(f"{RED}Invalid choice! Please select a valid number from the list.{RESET}")
     except KeyboardInterrupt:
          print(f"\n\n{BLUE}Exiting the tool...{RESET}")


 #------------------------------------------------------------------------------------

# | AP Scan | #

def scan_ap(interface):
     wifi_networks = []

     def scan_wifi(interface, conn):
          while True:
               try:
                    # Run the iw scan command with stderr redirected to stdout
                    command = f'iw dev {interface} scan 2>&1'
                    scan_result = os.popen(command).read()
                    if 'Device or resource busy' in scan_result or 'Operation not supported' in scan_result or 'Network is down' in scan_result or 'command failed' in scan_result:
                         # Continue scanning if an error occurs
                         continue
                    conn.send(scan_result)
                    conn.close()
                    break
               except KeyboardInterrupt:
                    conn.close()
                    break
     def loading_animation(conn):
          spinner = ['|', '/', '-', '\\']
          idx = 0
          try:
               # Shot the loading animation while scan not completed
               while True:
                    if conn.poll():
                         break
                    sys.stdout.write(f"\r{spinner[idx % len(spinner)]} Scanning for APs on {interface}")
                    sys.stdout.flush()
                    idx += 1
                    time.sleep(0.1)
          except KeyboardInterrupt:
               conn.close()
     
     parent_conn, child_conn = Pipe()
     scan_process = Process(target=scan_wifi, args=(interface, child_conn))
     animation_process = Process(target=loading_animation, args=(parent_conn,))
     
     scan_process.start()
     animation_process.start()
     scan_process.join()
     animation_process.join()
     
     # Get iw scan result
     scan = parent_conn.recv()
               
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
          ssid = ssid_match.group(1).strip() if ssid_match else None
          bssid = bssid_match.group(1).strip() if bssid_match else None
          signal = f'{round(float(signal_match.group(1).strip()))}' if signal_match else None
          channel = channel_match.group(1).strip() if channel_match else None
          frequency = round(float(frequency_match.group(1).strip())) if frequency_match else None
          auth = auth_match.group(1).strip() if auth_match else None
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
               elif (auth == 'PSK' or auth == 'IEEE 802.1X') and 'CCMP' in cipher:
                    encryption = 'WPA2'
               elif (auth == 'PSK' or auth == 'IEEE 802.1X') and 'TKIP' in cipher:
                    encryption = 'WPA'
               elif 'PSK' not in auth:
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

def list_ap(wifi_networks):
     # Create AP table
     table = PrettyTable()
     table.field_names = ["ID", "SSID", "BSSID", "Channel", "Signal (dBm)", "Band", "Encryption", "Auth", "Cipher"]
     for idx, ap in enumerate(wifi_networks):
          table.add_row([
               f"{idx}",
               ap['SSID'] or "N/A",
               ap['BSSID'] or "N/A",
               ap['Channel'] or "N/A",
               f"{ap['Signal']} dBm" if ap['Signal'] else "N/A",
               ap['Band'] or "N/A",
               ap['Encryption'] or "N/A",
               ap['Auth'] or "N/A",
               ap['Cipher'] or "N/A"
          ])

     print("Available Wi-Fi networks:")
     print(f"{MAGENTA}{table}{RESET}")
     print("\nPress [Ctrl + C] to stop")

 #------------------------------------------------------------------------------------

# | CODE | #

cmd_lenght = len(sys.argv)

if cmd_lenght > 1:
     if cmd_lenght == 2:
          command = sys.argv[1].lower()
          if command == "list":
               list_interfaces()
               print()
          else:
               print(f'{RED}Invalid Command! Type "wifighter [start/stop/status/list] [-INTERFACE_NAME-]"\n{RESET}')
     elif cmd_lenght == 3:
          command = sys.argv[1].lower()
          interface = sys.argv[2]

          if command == "start" or command == "stop": # Interface mode switch function
               monitor_switch('verbose', command, interface)
          elif command == "status": # Show interface mode status
               mode = interface_mode(interface)
               if mode:
                    print(f'{CYAN}Interface {interface} is {mode}\n{RESET}')
               else:
                    print(f'{RED}Interface "{interface}" does not exist! Type "wifighter [start/stop/status] [-INTERFACE_NAME-]"\n{RESET}')
          else:
               print(f'{RED}Invalid Command! Type "wifighter [start/stop/status] [-INTERFACE_NAME-]"\n{RESET}')
     else:
          print(f'{RED}Invalid Command! Type "wifighter [start/stop/status] [-INTERFACE_NAME-]"\n{RESET}')
else:
     introduction()
     # Choose scanning/attacking interface
     interface = choose_interface()

     # Scan and choose target AP
     if interface:
          # Make sure interface is in Managed mode
          #if interface_mode(interface) != 'Managed':
          monitor_switch(None, 'stop', interface)
          # Make sure NetworkManager is running
          start_services(None)

          try:
               while True:
                    # Get available AP's
                    scan_output = scan_ap(interface) # Get output array from iw
                    if scan_output and isinstance(scan_output, list):
                         wifi_networks = scan_output 
                    if wifi_networks:
                         print(wifi_networks)
                         introduction()
                         list_ap(wifi_networks) # Show available AP's in table
                    time.sleep(1) # Wait before each scan
          except KeyboardInterrupt:
               if wifi_networks:
                    target_ap = choose_target() # Let user choose AP as target
               else:
                    print(f"{RED}No AP's found, exiting...{RESET}\n")


     # List attack possibilities
     if target_ap:
          print(target_ap)

     
