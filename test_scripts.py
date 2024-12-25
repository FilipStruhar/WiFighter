#!venv/bin/python

from scapy.all import *
from scapy.all import Dot11

def sniff_clients(interface, target_ap):
    clients = set()

    def packet_handler(pkt):
        if pkt.haslayer(Dot11):
            # Check if the packet is a data frame and from/to the target BSSID
            if pkt.type == 2 and (pkt.addr2 == target_ap or pkt.addr1 == target_ap):
                if pkt.addr2 == target_ap and pkt.addr1 not in clients and pkt.addr1.lower() != 'ff:ff:ff:ff:ff:ff':
                    clients.add(pkt.addr1)
                    print(f"Client MAC Address: {pkt.addr1}")
                elif pkt.addr1 == target_ap and pkt.addr2 not in clients and pkt.addr2.lower() != 'ff:ff:ff:ff:ff:ff':
                    clients.add(pkt.addr2)
                    print(f"Client MAC Address: {pkt.addr2}")

    while True:
        # Start sniffing on the specified interface
        sniff(iface=interface, prn=packet_handler, timeout=5)  # Adjust timeout as needed
        
        print("\n\nConnected Clients:")
        for client in clients:
            print(client)
        print("----------")


# Example usage
target_ap = '----'
interface = '--------'
sniff_clients(interface, target_ap)




# With loading

from scapy.all import *
import multiprocessing
import sys
import time
from prettytable import PrettyTable

def sniff_clients(interface, target_ap, conn):
    clients = set()

    def packet_handler(pkt):
        if pkt.haslayer(Dot11):
            # Check if the packet is a data frame and from/to the target BSSID
            if pkt.type == 2 and (pkt.addr2 == target_ap or pkt.addr1 == target_ap):
                if pkt.addr2 == target_ap and pkt.addr1 not in clients and pkt.addr1.lower() != 'ff:ff:ff:ff:ff:ff':
                    clients.add(pkt.addr1)
                elif pkt.addr1 == target_ap and pkt.addr2 not in clients and pkt.addr2.lower() != 'ff:ff:ff:ff:ff:ff':
                    clients.add(pkt.addr2)

    # Start sniffing on the specified interface for a limited time
    sniff(iface=interface, prn=packet_handler, timeout=10)  # Adjust timeout as needed
    conn.send(list(clients))  # Send the list of clients through the connection
    conn.close()

def loading_animation(conn):
    spinner = ['|', '/', '-', '\\']
    idx = 0
    while True:
        if conn.poll():  # Check if sniffing is complete
            break
        sys.stdout.write(f"\r{spinner[idx % len(spinner)]} Sniffing for clients...")
        sys.stdout.flush()
        idx += 1
        time.sleep(0.1)
    sys.stdout.write("\r")  # Clear the line
    sys.stdout.flush()

def list_clients(sniffed_clients):
    # Create AP table
    table = PrettyTable()
    table.field_names = ["ID", "Client MAC"]
    for idx, client_mac in enumerate(sniffed_clients):
        table.add_row([f"{idx}", client_mac or "N/A"])

    print(f"| Client Scan |")
    print(f"{table}")
    print("\nPress [Ctrl + C] to stop")

def choose_target_client():
    global sniffed_clients
    while True:     
        try:
            # Prompt the user to choose an interface by number
            choice = int(input(f"\n\nTarget client number: "))
            # Check if the choice is in range
            if 0 <= choice < len(sniffed_clients):
                target_client = sniffed_clients[choice]
                return target_client  # Return chosen interface
            else:
                print("Invalid choice! Please select a valid number from the list.")
        except ValueError:
            print("Invalid input! Please enter a valid number.")
        except KeyboardInterrupt:
            print("\n\nExiting the tool...")
            break

def handshake_crack(target_ap, interface, deauth_mode):
    # Prepare variables
    ssid = target_ap['SSID'] if target_ap['SSID'] else None
    bssid = target_ap['BSSID'] if target_ap['BSSID'] else None
    target = ssid if ssid else bssid  # Set target by checking if SSID set
    channel = target_ap['Channel'] if target_ap['Channel'] else None
    deauth_mode = deauth_mode.lower()
    target_client = None

    monitor_switch(None, 'start', interface)  # Make sure interface is in Monitor
    stop_services(None)  # Make sure interfering services are not running

    if deauth_mode == 'client deauth' and not target_client:
        global sniffed_clients
        try:
            while True:
                parent_conn, child_conn = multiprocessing.Pipe()
                sniff_process = multiprocessing.Process(target=sniff_clients, args=(interface, bssid, child_conn))
                loading_process = multiprocessing.Process(target=loading_animation, args=(parent_conn,))

                # Start sniffing and loading animation processes
                sniff_process.start()
                loading_process.start()

                sniff_process.join()  # Wait for sniffing to complete
                loading_process.join()  # Wait for loading animation to complete

                # Get the list of clients from the sniffing process
                sniffed_clients = parent_conn.recv()
                
                if sniffed_clients:
                    logo()
                    list_clients(sniffed_clients)  # Show available clients in table
                time.sleep(5)
        except KeyboardInterrupt:
            if sniffed_clients:
                target_client = choose_target_client()  # Let user choose client as target
            else:
                print("\n\nNo clients found, exiting...")

# Example usage of handshake_crack
target_ap = {
    'SSID': 'ExampleSSID',
    'BSSID': '00:11:22:33:44:55',
    'Channel': '6'
}
interface = 'wlan0mon'  # Replace with your actual interface name in monitor mode
deauth_mode = 'client deauth'
handshake_crack(target_ap, interface, deauth_mode)


