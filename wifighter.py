#!/usr/bin/env python3

# | GRAPHICS | #

# Colors
RED = '\033[31m'
GREEN = '\033[32m'
YELLOW = '\033[33m'
BLUE = '\033[34m'
MAGENTA = '\033[35m'
CYAN = '\033[36m'
RESET = '\033[0m'

# Logo
LOGO = """
 __      __._____________.__       .__     __                
/  \    /  \__\_   _____/|__| ____ |  |___/  |_  ___________ 
\   \/\/   /  ||    __)  |  |/ ___\|  |  \   __\/ __ \_  __ )
 \        /|  ||     \   |  / /_/  >   Y  \  | \  ___/|  | \/
  \__/\  / |__|\___  /   |__\___  /|___|  /__|  \___  >__|   
       \/          \/      /_____/      \/          \/                                                                           
"""


# | IMPORT | #

import subprocess, os, time


# | INTRODUCTION | #

# Show logo
print(f"{RED}{LOGO}{RESET}")
print("")
print(f"{RED}Welcome :D This is WiFighter!{RESET}")
print(f"{RED}Easy-to-use WiFI pen-testing tool{RESET}")
print(" ")
print(f"{YELLOW}Build by TeeFox | https://github.com/FilipStruhar{RESET}")



# | VARIABLES | #


# | CODE | #

# Run capture.py and wait for it to complete
#subprocess.run(['python3', 'WPA_crack.py'])