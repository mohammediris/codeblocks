from scapy.all import ARP, Ether, sniff
import subprocess
import sys

def set_ip_to_dhcp(interface_name):
    try:
        # Build the netsh command to set IP address to DHCP
        command1 = f"netsh interface ipv4 set address name=\"{interface_name}\" source=dhcp"
        command2 = f"netsh interface ipv4 set interface {interface_name}"
        # Execute the command
        subprocess.run(command1, check=True, shell=True)
        subprocess.run(command2, check=True, shell=True)
        print(f"Successfully set IP address of {interface_name} to DHCP.")
    except subprocess.CalledProcessError as e:
        print(f"Error setting IP address to DHCP: {e}")
        
def arp_display(pkt):
    if ARP in pkt and pkt[ARP].op == 1:  # If it's an ARP request (who-has)
        print(f"IP Address: {pkt[ARP].psrc}")
        
if __name__ == "__main__":

    interface_name = "Wi-Fi" 
    set_ip_to_dhcp(interface_name)

    # Set the network interface to sniff on (replace with your interface)
    interface = "Intel(R) Wi-Fi 6 AX201 160MHz"

    # Start sniffing ARP packets
    try:
        sniff(filter="arp", prn=arp_display, store=0, iface=interface)
        # sniff(prn=arp_broadcast_callback, filter="arp", store=0, iface=interface)
    except KeyboardInterrupt:
        sys.exit()
