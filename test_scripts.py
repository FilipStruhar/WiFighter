#!venv/bin/python

def sniff_clients(interface, target_ap):
    # Standardized MAC addresses in networking (communication with .startswith(these) won't appear as a result of the sniffing)
    standardized_MACs = ['ff:ff:ff:ff:ff:ff', '01:80:c2:00:00:00', '01:80:c2:00:00:0e', '01:00:5e', '33:33']
    interrupted = False

    clients = set()
    def packet_handler(pkt):
        if pkt.haslayer(Dot11):
            # Check if the packet is a data frame
            if pkt.type == 2: 
                if pkt.addr2 == target_ap and pkt.addr1 not in clients: 
                    # Check if not one of the standardized MAC addresses
                    if not any(pkt.addr1.startswith(mac) for mac in standardized_MACs): 
                            print(f'2 {pkt.addr2} = {target_ap}, | {pkt.addr1} |')
                            #client = f'{pkt.addr2} -> {pkt.addr1}' # AP MAC -> Client MAC
                            clients.add(pkt.addr1)

                elif pkt.addr1 == target_ap and pkt.addr2 not in clients:
                    # Check if not one of the standardized MAC addresses
                    if not any(pkt.addr1.startswith(mac) for mac in standardized_MACs):
                            print(f'1 {pkt.addr1} = {target_ap}, | {pkt.addr2} |')
                            #client = f'{pkt.addr1} -> {pkt.addr2}' # AP MAC -> Client MAC
                            clients.add(pkt.addr2)
    print('Start sniffing')
    try:
        sniff(iface=interface, prn=packet_handler, timeout=8)  # Start sniffing on the specified interface
    except KeyboardInterrupt:
        print('Keyboard interrupt in sniff caught!')
        interrupted = True
    print('Stop sniffing')
    print(f'Sniff: interrupted {interrupted}')
    return list(clients), interrupted




