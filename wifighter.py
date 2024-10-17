#!venv/bin/python

# | IMPORT | #

import os, sys, subprocess, time, scapy, pywifi

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

detected_interfaces = []
interface = None
interface_name = None
wifi = pywifi.PyWiFi()

 #------------------------------------------------------------------------------------

 # | INTRODUCTION | #

def introduction():
     os.system("clear")

     # | INTRODUCTION | #

     # Show logo
     print(f"{ORANGE}{LOGO}{RESET}")
     print("")
     print(f"{ORANGE}Welcome :D This is WiFighter!{RESET}")
     print(f"{ORANGE}Easy-to-use WiFi pen-testing security tool{RESET}")
     print(" ")
     print(f"{MAGENTA}Build by Filip Struhar | https://github.com/FilipStruhar{RESET}")

     print(" ")
     print(" ")

#---------------------------------

 # | MONITOR MODE | #

def interface_mode(iface):
     mode = None

     output = os.popen(f'iwconfig {iface} 2>/dev/null').read()
     for line in output.splitlines():
          if 'Mode' in line:
               if 'Managed' in line:
                    mode = 'Managed'
               elif 'Monitor' in line:
                    mode = 'Monitor'
               break

     return mode


def monitor_switch(command, iface):

     # Determine interface mode
     mode = interface_mode(iface)

     if mode:
          if command == "start" and mode == "Managed":
               print("Switch")
          elif command == "start":
               print(f'{ORANGE}Interface {iface} is already in Monitor Mode, skipping...{RESET}')
          
          if command == "stop" and mode == "Monitor":
               print("Switch")
          elif command == "stop":
               print(f'{ORANGE}Interface {iface} is already in Managed Mode, skipping...{RESET}')
               
     else:
          print(f'{RED}Non-Existant Interface Name! Retype "wifigter [start/stop] [-INTERFACE_NAME-]"{RESET}')

#---------------------------------

 # | INTERFACE CHOOSE | #

def choose_interface(detected_interfaces):
     # Build array of detected wifi interfaces
     for interface in wifi.interfaces():
          detected_interfaces.append({
               'Name':interface.name(),
               'Interface': interface
          })

     idx = 1
     # Show detected interfaces
     print("Available Wi-Fi Interfaces:")
     for interface in detected_interfaces:
          print(f"{idx}. {interface['Name']}")
          idx += 1

     while True:     
          
          try:
               # Prompt the user to choose an interface by number
               choice = int(input("\nSelect the interface number: ")) - 1
          except ValueError:
               print("Invalid input! Please enter a valid number.\n")
               continue
          
          # Check if the choice is in range
          if 0 <= choice < len(detected_interfaces):
               # Return chosen interface
               interface = detected_interfaces[choice]['Interface']
               interface_name = detected_interfaces[choice]['Name']
               return interface, interface_name
          else:
               print("Invalid choice! Please select a valid number from the list.\n")
          


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
          iface = sys.argv[2]

          if command == "start" or command == "stop":
               # Call monitor switch function
               monitor_switch(command, iface)
          else:
               print(f'{RED}Invalid Command! Type "wifigter [start/stop] [-INTERFACE_NAME-]"{RESET}')
     else:
          print(f'{RED}Invalid Command! Type "wifigter [start/stop] [-INTERFACE_NAME-]"{RESET}')
else:

     # Show logo
     introduction()

     # Let the user choose scanning interface
     try: 
          interface, interface_name = choose_interface(detected_interfaces)
     except:
          print(f"\n\n{ORANGE}Exiting the tool...{RESET}")

     if interface and interface_name:
          # Scan APs
          try:
               while True:
                    
                    interface.scan()  # Start scanning
                    
                    # Get scan results
                    scan_results = interface.scan_results()
                   
                    ap_list = []

                    for network in scan_results:
                         ap_list.append({
                              'SSID': network.ssid,
                              'BSSID': network.bssid,
                              'Signal': network.signal,
                              'Band': network.freq,
                              'Auth': network.auth,
                              'Cipher': network.cipher,
                              'AKM': network.akm
                         })
                    
                    # Clear the screen
                    os.system("clear")

                    # Print the AP list
                    print("Available Wi-Fi networks:")
                    for ap in ap_list:
                         print(f"SSID: {ap['SSID']}, BSSID: {ap['BSSID']}, Signal: {ap['Signal']} dBm, Band: {ap['Band']} MHz, Auth: {ap['Auth']}, Cipher: {ap['Cipher']}, AKM: {ap['AKM']}")


                    # Wait before the next scan
                    print("\nPress [Ctrl + C] to stop")

                    # Refresh rate
                    time.sleep(4)
          
          except KeyboardInterrupt:
               print(f"\n\n{ORANGE}Exiting the scan...{RESET}")
