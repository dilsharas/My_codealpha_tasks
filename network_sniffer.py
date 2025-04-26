import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP, ICMP
import sys
import os
import time

# Function to create logs folder if it doesn't exist
def create_log_folder():
    log_folder = "C:\\assigmment turnitind final\\Code alpha Task\\logs"
    if not os.path.exists(log_folder):
        os.makedirs(log_folder)

# Function to write logs to file
def write_log(log_message):
    log_folder = "C:\\assigmment turnitind final\\Code alpha Task\\logs"
    log_file = os.path.join(log_folder, "packet_logs.txt")
    with open(log_file, "a") as log:
        log.write(log_message + "\n")

# Function to get the network interface
def get_interface():
    """Prompt user to select a network interface by index."""
    try:
        interfaces = scapy.get_if_list()
        print("Available interfaces:")
        for idx, iface in enumerate(interfaces):
            print(f"{idx}: {iface}")
        choice = int(input("Select the interface number: "))
        return interfaces[choice]
    except Exception as e:
        print(f"Error retrieving interfaces: {e}")
        sys.exit(1)

# Function to add a Packet Filtering Menu
def packet_filtering_menu():
    """Allow the user to set packet filters."""
    print("\nPacket Filtering Options:")
    print("1: Filter by Source IP")
    print("2: Filter by Destination IP")
    print("3: Filter by Protocol (TCP/UDP/ICMP)")
    print("4: No Filter (Capture all packets)")

    filter_choice = input("Enter your choice: ")

    if filter_choice == "1":
        src_ip = input("Enter Source IP to filter: ")
        return f"src host {src_ip}"
    elif filter_choice == "2":
        dst_ip = input("Enter Destination IP to filter: ")
        return f"dst host {dst_ip}"
    elif filter_choice == "3":
        proto = input("Enter Protocol (TCP/UDP/ICMP): ").upper()
        if proto == "TCP":
            return "tcp"
        elif proto == "UDP":
            return "udp"
        elif proto == "ICMP":
            return "icmp"
        else:
            print("Invalid Protocol")
            return ""
    elif filter_choice == "4":
        return ""  # No filter
    else:
        print("Invalid choice. Capturing all packets.")
        return ""

# Function to detect suspicious packets (basic IDS)
def detect_suspicious(packet):
    """Detect suspicious packets, like abnormal ports."""
    try:
        if packet.haslayer(TCP):
            if packet[TCP].dport == 80 and len(packet[scapy.Raw].load) > 1500:
                return "Suspicious HTTP traffic: Large payload"
            elif packet[TCP].dport == 53:  # DNS port, look for unusual DNS queries
                return "Suspicious DNS request"
        elif packet.haslayer(ICMP):
            return "Suspicious ICMP packet detected"
        return None
    except Exception as e:
        print(f"Error in suspicious packet detection: {e}")
        return None

# Function to process each packet
def process_packet(packet):
    """Analyze and display packet details."""
    try:
        log_message = ""
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = packet[IP].proto
            proto_name = "Unknown"
            src_port = dst_port = "Unknown"

            if protocol == 6 and packet.haslayer(TCP):
                proto_name = "TCP"
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
            elif protocol == 17 and packet.haslayer(UDP):
                proto_name = "UDP"
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
            elif protocol == 1 and packet.haslayer(ICMP):
                proto_name = "ICMP"
                src_port = dst_port = "N/A"
            else:
                src_port = dst_port = "Unknown"

            log_message = f"Source: {src_ip}:{src_port} -> Destination: {dst_ip}:{dst_port} | Protocol: {proto_name}"

            # Log the HTTP payload if available
            if packet.haslayer(TCP) and packet[TCP].dport == 80 and packet.haslayer(scapy.Raw):
                log_message += f" | HTTP Payload: {packet[scapy.Raw].load[:50]}..."

            # Check for suspicious packets
            suspicious_message = detect_suspicious(packet)
            if suspicious_message:
                log_message += f" | ALERT: {suspicious_message}"

            # Print and log the packet details
            print(log_message)
            write_log(log_message)
    except Exception as e:
        print(f"Error processing packet: {e}")

# Function to start the sniffer with the selected interface and filter
def start_sniffer(interface, packet_count=10, filter=""):
    """Start sniffing packets on the specified interface."""
    try:
        print(f"Starting sniffer on {interface}... Press Ctrl+C to stop.")
        scapy.sniff(iface=interface, prn=process_packet, filter=filter, count=packet_count)
    except KeyboardInterrupt:
        print("\nSniffer stopped by user.")
    except Exception as e:
        print(f"Error during sniffing: {e}")
        sys.exit(1)

# Main function to run the sniffer
def main():
    """Main function to run the sniffer."""
    print("=== Advanced Network Sniffer ===")

    # Create log folder if not exists
    create_log_folder()

    interface = get_interface()

    # Get packet filter from the user
    filter = packet_filtering_menu()

    try:
        packet_count = int(input("Enter number of packets to capture (default 10): ") or 10)
    except ValueError:
        packet_count = 10

    # Start the packet sniffer
    start_sniffer(interface, packet_count, filter)

if __name__ == "__main__":
    main()
