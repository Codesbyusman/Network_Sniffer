import scapy.all as scapy 
from argparse import RawTextHelpFormatter
import argparse
from scapy.layers import http, inet, dhcp, dns, tls
from scapy.layers.l2 import Ether 
import time #for seleeping system 

#coloring 
from colorama import Fore, Back, Style

#this function is used for sniffing
def sniff(interface, filters):
    scapy.sniff(iface=interface, store=False,
                prn=process_sniffed_packets, filter=filters)

#for getting the url
def get_url(packet):

    # print(scapy.packet.getlayer())i
    url = (packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path)
    print(url)
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
# A function that returns the Source Ip of the Packet


def get_src_ip(packet):
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
        # Check if there is Destination Ip then Return it!
        if inet.IP in packet:
            return packet[inet.IP].dst
    except:
        return "Hidden Destination Ip"
    # return "4"#packet[http.IP].src

# A function that Returns the Source Port


def get_src_port(packet):
    try:
        if inet.TCP in packet:
            return packet[inet.TCP].sport
    except:
        return "Hidden Source Port"
# A function that returns the Destination Port


def get_des_port(packet):
    # proto_field = packet.get_field('proto')
    # print(proto_field.i2s[packet.proto])
    try:
        if inet.TCP in packet:

            # return proto_field.i2s[pkt.proto]
            return packet[inet.TCP].dport
    except:
        return "Hidden Destination Port"

# A function that returns the Sequence Number


def get_seq_number(packet):
    # proto_field = packet.get_field('proto')
    # print(proto_field.i2s[packet.proto])
    try:
        if inet.TCP in packet:

            # return proto_field.i2s[pkt.proto]
            return packet[inet.TCP].seq
    except:
        return "Hidden Sequence Number"

        # A function that returns the Ack Number


def get_ack_number(packet):
    # proto_field = packet.get_field('proto')
    # print(proto_field.i2s[packet.proto])
    try:
        if inet.TCP in packet:

            # return proto_field.i2s[pkt.proto]
            return packet[inet.TCP].ack
    except:
        return "Hidden Acknowledge Number"


def html_injection_test(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        # Testing if there is some HTML injection Possible
        html_injections = ["<h1>", "<h2>", "<h1>", "%3C%2F", "%3CHTML%3E", "%3C%2FHTML%3E", "%3E", "%3CH1%3E", "%3C%2FH1%3E", "<HTML>", "</HTML>", "%3CH2%3E",
                           "%3C%2FH2%3E", "%3CH3%3E", "%3C%2FH3%3E", "%3CH4%3E", "%3C%2FH4%3E", "%3CH5%3E", "%3C%2FH5%3E", "%3CH6%3E", "%3C%2FH6%3E", "</h2>", "%3CBR%3E", "%3CHR%3E"]
        for html_injection in html_injections:
            try:
                if html_injection in load.decode("utf-8"):
                    return load
            except:
                break


def sql_injection_test(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        # Testing if there is some HTML injection Possible
        sql_injections = ["page.asp?id=1 or 1=1",
                          "page.asp?id=1' or 1=1",
                          "page.asp?id=1\" or 1=1",
                          "page.asp?id=1 and 1=2",
                          "%22page.asp%3Fid%3D1%20or%201%3D1%22%2C%0A",
                          "page.asp%3Fid%3D1%27%20or%201%3D1",
                          "page.asp%3Fid%3D1%20or%201%3D1",
                          "page.asp%3Fid%3D1%22%20or%201%3D1",
                          "page.asp%3Fid%3D1%20and%201%3D2",
                          "%22",
                          "\"",
                          "'",
                          "%27",
                          "#",
                          "%23",
                          ";",
                          "%3B",
                          "%%2727",
                          "%25%27"
                          ]
        for sql_injection in sql_injections:
            try:
                if sql_injection in load.decode("utf-8"):
                    return load
            except:
                break


def xxe_injection_test(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        # Testing if there is some xee injection Possible
        xxe_injections = ["<!DOCTYPE",
                          "%3C%21DOCTYPE",
                          "[<!ENTITY",
                          "%5B%3C%21ENTITY",
                          "%5D%3E",
                          "]>",
                          "<?xml",
                          "%3C%3Fxml"
                          ]
        for xxe_injection in xxe_injections:
            try:
                if xxe_injection in load.decode("utf-8"):
                    return load
            except:
                break




def js_injection_test(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        # Testing if there is some HTML injection Possible
        js_injections = ["<script>",
                         "%3Cscript%3E",
                         "</script>",
                         "%3C%2Fscript%3E",
                         "document.location",
                         "<?php",
                         "%3C%3Fphp",
                         "<img",
                         "%3Cimg",
                         "console.log",
                         "alert",
                         "alert(",
                         "alert%28",
                         "eval",
                         "<svg",
                         "%3Csvg",
                         "<div",
                         "%3Cdiv"
                         ]
        for js_injection in js_injections:
            try:
                if js_injection in load.decode("utf-8"):
                    return load
            except:
                break


def xpath_injection_test(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        # Testing if there is some xpath_injection_test Possible
        xpath_injections = [
            "' or '1'='1",
            "%27%20or%20%271%27%3D%271",
            "' or ''='",
            "%27%20or%20%27%27%3D%27",
            "' or 1=1 or 'x'='y",
            "%27%20or%201%3D1%20or%20%27x%27%3D%27y",
            "/",
            "%2F",
            "//",
            "%2F%2F",
            "//*",
            "%2F%2F%2A",
            "*/*",
            "%2A%2F%2A",
            "@*",
            "%40%2A"

        ]
        for xpath_injection in xpath_injections:
            try:
                if xpath_injection in load.decode("utf-8"):
                    return load
            except:
                break


def command_injection_test(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        # Testing if there is some HTML injection Possible
        command_injections = [
            "cat \\",
            "cat%20%2F",
            ":root",
            "%3Aroot",
            "/bin",
            "%2Fbin",
            "/sh",
            "%2Fsh",
            "/dev",
            "%2Fdev",
            "/root",
            "%2Froot",
            "/",
            "%2F"
        ]
        for command_injection in command_injections:
            try:
                if command_injection in load.decode("utf-8"):
                    return load
            except:
                break


def xslt_injection_test(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        # Testing if there is some xslt_injection_test
        xslt_injections = [
            "<xsl:",
            "%3Cxsl%3A",
            "<xsl",
            "%3Cxsl"
        ]
        for xslt_injection in xslt_injections:
            try:
                if xslt_injection in load.decode("utf-8"):
                    return load
            except:
                break


def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        keywords = ["username", "user", "password", "pass", "login", "eid" , "pswd"]

        for keyword in keywords:
            try:
                if keyword in load.decode("utf-8"):
                    return load
            except:
                break
# A function that Runs after the packet has been catch


def process_sniffed_packets(packet):
    if packet.haslayer(inet.UDP):
        print(Fore.BLUE)
        print("UDP Packet Captured..Header")
        print("Source Port: "+str(packet[inet.UDP].sport))
        print("Destination Port: " + str(packet[inet.UDP].dport))
    if packet.haslayer(dns.DNS):
        print(Fore.GREEN)
        print(packet[dns.DNS].summary())
    if packet.haslayer(inet.ICMP):
        print(Fore.YELLOW)
        icmp = packet[inet.ICMP].summary()
        size = len(icmp)
        icmp = icmp[: size-7]
        print(icmp)
    if packet.haslayer(dhcp.BOOTP):
        print(Fore.CYAN)
        print("Request Goes to the DHCP Server")
        print("IP Address In Use: " + packet[dhcp.BOOTP].ciaddr)
        print("New Ip Address " + packet[dhcp.BOOTP].yiaddr)

    if packet.haslayer(http.HTTPRequest):
        print(scapy)
        # print(packet[inet.IP].show())
        # Getting the Information and Printing it
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

        html_inj = html_injection_test(packet)
        sql_inj = sql_injection_test(packet)
        js_inj = js_injection_test(packet)
        xxe_inj = xxe_injection_test(packet)
        comm_inj = command_injection_test(packet)
        xslt_inj = xslt_injection_test(packet)
        xpath_inj = xpath_injection_test(packet)
        if login_info:
            print(Fore.RED)
            print(b"nn[+] Possible username/password >" + login_info + b"nn")
            time.sleep(2)
            print( Fore.MAGENTA)
        if html_inj:
            print( Fore.MAGENTA)
            print(
                b"HTML Injection Attack In the Above Request {-} String: " + html_inj)
            time.sleep(0.5)
        if sql_inj:
            print( Fore.YELLOW)
            print(
                b"SQL Injection Attack In the Above Request {-} String: " + sql_inj)
            time.sleep(0.5)
        if js_inj:
            print( Fore.GREEN)
            print(
                b"XSS Attack Attempt In the Above Request {-} String: " + js_inj)
            time.sleep(0.5)
        if(xxe_inj):
            print( Fore.BLUE )
            print(
                b"XEE Attack Attempt In the Above Request {-} String: " + xxe_inj)
            time.sleep(0.5)
        if(comm_inj):
            print( Fore.YELLOW)
            print(
                b"Command Injection In the Above Request {-} String: " + comm_inj)
            time.sleep(0.5)
        if(xslt_inj):
            print( Fore.GREEN )
            print(
                b"XSLT Detected In the Above Request {-} String: " + xslt_inj)
            time.sleep(0.5)
        if(xpath_inj):
            print( Fore.MAGENTA )
            print(
                b"XPATH Detected In the Above Request {-} String: " + xpath_inj)
            time.sleep(0.5)
            # If the packet has layer then
    if packet.haslayer(http.HTTPResponse):
        # print(packet[inet.TCP].show())

        print(Fore.MAGENTA + "\n\t\t --------------------------------------------------------------\n")
        
        print("[+] HTTP Response >> " +
              (packet[http.HTTPResponse].Status_Code).decode("utf-8"))
        if inet.IP in packet:
            
            print(Fore.YELLOW + "[+]" + Fore.GREEN + " Source Ip           : " + packet[inet.IP].src)
            print(Fore.YELLOW + "[+]" + Fore.GREEN + " Source Ip           : " + packet[inet.IP].dst)
        if inet.TCP in packet:
            print(Fore.YELLOW + "[+]" + Fore.GREEN + " Source Port         : " + str(packet[inet.TCP].sport))
            print(Fore.YELLOW + "[+]" + Fore.GREEN + " Destination Port    : " + str(packet[inet.TCP].dport))
            print(Fore.YELLOW + "[+]" + Fore.GREEN + " Sequence Number     : " + str(packet[inet.TCP].seq))
            print(Fore.YELLOW + "[+]" + Fore.GREEN + " Acknowledge Number  : " + str(packet[inet.TCP].ack))

        print( Fore.MAGENTA + "\n\t\t --------------------------------------------------------------\n")

parser = argparse.ArgumentParser(formatter_class=RawTextHelpFormatter)
parser.add_argument("-i", "--interface", dest="interface",
                        help="Specify interface on which to sniff packets")
parser.add_argument("-f", "--filters", dest="filters",
                        help="Specify The filters for the usage\nList of Filters:\n   1) port [Number]  .. \nExample \n port 443 or port 80 \n 2) port Range [Range]..\n Example \n portrange 1000-5000 \n 3) tcp \n 4)udp \n5) icmp \n You can use combinations as well.")

arguments = parser.parse_args()
if not (arguments.filters):
    arguments.filters = None
if arguments.filters != None:
    print("Filter is: " + arguments.filters)
sniff(arguments.interface, arguments.filters)