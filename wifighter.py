#!venv/bin/python

import os, subprocess, time, scapy, pywifi

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


# | IMPORT | #

import subprocess, os, time

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


# | VARIABLES | #


# | CODE | #

detected_interfaces = []
interface = None
interface_name = None
wifi = pywifi.PyWiFi()

def choose_interface(detected_interfaces):
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
          

# Build array of detected wifi interfaces
for interface in wifi.interfaces():
    detected_interfaces.append({
        'Name':interface.name(),
        'Interface': interface
    })

# Let the user choose an interface
try: 
     interface, interface_name = choose_interface(detected_interfaces)
except:
     print(f"\n\n{ORANGE}Exiting the scan...{RESET}")

if interface and interface_name:
    print(f"The selected interface is: {interface}")
    print(f"The selected interface is: {interface_name}")

