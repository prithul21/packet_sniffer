from scapy.all import sniff, IP, TCP, UDP, ICMP

# Callback function to handle packets
def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto
        
        print(f"\nSource IP: {ip_src}")
        print(f"Destination IP: {ip_dst}")
        
        # Check for the protocol type
        if proto == 6:  # TCP
            print("Protocol: TCP")
            if TCP in packet:
                payload = packet[TCP].payload
                print(f"Payload: {bytes(payload)}")
                
        elif proto == 17:  # UDP
            print("Protocol: UDP")
            if UDP in packet:
                payload = packet[UDP].payload
                print(f"Payload: {bytes(payload)}")
                
        elif proto == 1:  # ICMP
            print("Protocol: ICMP")
        else:
            print("Protocol: Other")

# Function to start sniffing
def start_sniffing(interface=None):
    # Sniff on the specified interface, or use default
    print("Starting packet capture...")
    sniff(prn=packet_callback, iface=interface, store=False)

# Specify the network interface to listen on
start_sniffing(interface="Ethernet 3")
