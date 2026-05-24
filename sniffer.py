from scapy.all import sniff, IP, TCP, UDP, ICMP # Import necessary layers from Scapy

def packet_callback(packet):# Callback function to process each captured packet
    if IP in packet:# Check if the packet has an IP layer
        src_ip = packet[IP].src # Get source IP address
        dst_ip = packet[IP].dst # Get destination IP address
        proto = packet[IP].proto # Get protocol number

        print("-" * 50) # Print a separator for better readability
        print(f"Source IP      : {src_ip}") # Print source IP address
        print(f"Destination IP : {dst_ip}") # Print destination IP address

        if TCP in packet: # Check if the packet has a TCP layer
            print("Protocol       : TCP")
            print(f"Source Port    : {packet[TCP].sport}")
            print(f"Dest Port      : {packet[TCP].dport}")
            # Get payload if exists
            if packet[TCP].payload: # Check if there is a payload in the TCP layer
                payload = bytes(packet[TCP].payload) # Convert payload to bytes
                print(f"Payload (raw)  : {payload[:50]}") # Print the first 50 bytes of the payload (if it exists)

        elif UDP in packet: # Check if the packet has a UDP layer
            print("Protocol       : UDP")
            print(f"Source Port    : {packet[UDP].sport}")
            print(f"Dest Port      : {packet[UDP].dport}")

        elif ICMP in packet: # Check if the packet has an ICMP layer
            print("Protocol       : ICMP (Ping)")

        else: # If the protocol is not TCP, UDP, or ICMP, print it as Other
            print(f"Protocol       : Other (proto={proto})")

print("=" * 50) # Print a header for the sniffer output
print("  Network Sniffer Started — CodeAlpha Task 1")
print("  Press Ctrl+C to stop")
print("=" * 50)

# Capture 30 packets, then stop automatically
sniff(prn=packet_callback, store=0, count=30)