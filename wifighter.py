#!venv/bin/python

# | IMPORT | #

import os, sys, subprocess, time, scapy
from prettytable import PrettyTable

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

 # | INTERFACE CHOOSE | #

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
                    choice = int(input("\nSelect the interface number: ")) - 1
               except ValueError:
                    print("Invalid input! Please enter a valid number.\n")
                    continue
               
               # Check if the choice is in range
               if 0 <= choice < len(detected_interfaces):
                    # Return chosen interface
                    interface = detected_interfaces[choice]
                    return interface
               else:
                    print("Invalid choice! Please select a valid number from the list.\n")
     except:
          print(f"\n\n{ORANGE}Exiting the tool...{RESET}")


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
     print(interface)

     
