from os import access
import scapy.all as scapy
import sys
import argparse
from scapy.layers import http,inet,dhcp,dns,tls 
from scapy.layers.l2 import Ether
import socket
import threading
import signal
import sys
import os
from urllib.parse import unquote


proxy = 'http://127.0.0.1:8000'

os.environ['http_proxy'] = proxy 
os.environ['HTTP_PROXY'] = proxy
os.environ['https_proxy'] = proxy
os.environ['HTTPS_PROXY'] = proxy

print("OKAY..")
#your code goes here.............

config =  {
            "HOST_NAME" : "http://127.0.0.1",
            "BIND_PORT" : 8000,
            "MAX_REQUEST_LEN" : 4096, 
            "CONNECTION_TIMEOUT" : 10,
            "BLACKLIST_DOMAINS":["http://testasp.vulnweb.com/", "http://testasp.vulnweb.com/"]
          }



def get_interface():
    
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", dest="interface", help="Specify interface on which to 	sniff packets")
    arguments = parser.parse_args()
    return arguments.interface
    
def sniff(interface):
    load_layer("tls")
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packets)
    


def get_url(packet):
    
    #print(scapy.packet.getlayer())i
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
        keywords = ["username", "user", "password", "pass", "login"]
        
        for keyword in keywords:
            try:
                if keyword in load.decode("utf-8"):
                    return load
            except:
                break
# A function that Runs after the packet has been catch
def process_sniffed_packets(packet):
    if packet.haslayer(tls):
        print(packet[tls].show())
    print("++++++++++++++++++++++++++++++++++++haa")
    if packet.haslayer(inet.UDP):
        print("UDP Packet Captured..Header")
        print("Source Port: "+str(packet[inet.UDP].sport))
        print("Destination Port: "+ str(packet[inet.UDP].dport))
    if packet.haslayer(dns.DNS):
        print(packet[dns.DNS].summary())
    if packet.haslayer(inet.ICMP):
        icmp = packet[inet.ICMP].summary()
        size = len(icmp)
        icmp = icmp[:size-7]
        print(icmp)
    if packet.haslayer(dhcp.BOOTP):
        print("Request Goes to the DHCP Server")
        print("IP Address In Use: " + packet[dhcp.BOOTP].ciaddr)
        print("New Ip Address " + packet[dhcp.BOOTP].yiaddr)
      
      
    if packet.haslayer(http.HTTPRequest):
        print(scapy)
        #print(packet[inet.IP].show())
        #Getting the Information and Printing it
        print("\n--------------------------------------------\n")
        url = get_url(packet)
        ip_src =  get_src_ip(packet)
        ip_des =  get_des_ip(packet)
        port_src = get_src_port(packet)
        port_des = get_des_port(packet)
        seq_num = get_seq_number(packet)
        ack_num = get_ack_number(packet)
        print("[+] HTTP Request >>" + url.decode("utf-8"))
        print("[+]Source Ip : " + ip_src)
        print("[+]Destination Ip : " + ip_des)
        print("[+]Source Port : " + str(port_src))
        print("[+]Destination Port : " + str(port_des))
        print("[+]Sequence Number : " + str(seq_num))
        print("[+]Acknowledge Number : " + str(ack_num))
        print("\n--------------------------------------------\n")
        login_info = get_login_info(packet)
        if login_info:
            print(b"nn[+] Possible username/password >" + login_info + b"nn")

            #If the packet has layer then
    if packet.haslayer(http.HTTPResponse):
            #print(packet[inet.TCP].show())

        print("[+] HTTP Response >> " +  (packet[http.HTTPResponse].Status_Code).decode("utf-8"))
        if inet.IP in packet:
            
            print("[+]Source Ip : " + packet[inet.IP].src)
            print("[+]Source Ip : " + packet[inet.IP].dst)
        if inet.TCP in packet:   
            print("[+]Source Port : " + str(packet[inet.TCP].sport))
            print("[+]Destination Port : " + str(packet[inet.TCP].dport))
            print("[+]Sequence Number : " + str(packet[inet.TCP].seq))
            print("[+]Acknowledge Number : " + str(packet[inet.TCP].ack))

iface = get_interface()
sniff(iface)



class Server:
    """ The server class """
    #PART1: Creating a socket for the server
    #We will now do it in a function
    #and to listene to a max of 10 clients at a time

    def __init__(self, config):

        signal.signal(signal.SIGINT, self.shutdown)     # Shutdown on Ctrl+C
        self.serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)             # Create a TCP socket
        self.serverSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)    # Re-use the socket
        self.serverSocket.bind((config['HOST_NAME'], config['BIND_PORT'])) # bind the socket to a public host, and a port
        self.serverSocket.listen(10)    # become a server socket
        self.__clients = {}


    def listen_for_client(self):
        """ Wait for clients to connect """
        #PART 2:LISTEN FOR CLIENT We wait for the clients connection request and once a
        #successful connection is made we dispatch the request in a separate thread,
        #making ourselves available for the next request.
        #This allows us to handle multiple requests simultaneously which boosts the performance of the 
        #server multifold times. -> we need a function for threading and to get client name!!!


        while True:
            (clientSocket, client_address) = self.serverSocket.accept()   # Establish the connection
            
            d = threading.Thread(name=self._getClientName(client_address), target=self.proxy_thread, args=(clientSocket, client_address))
            d.setDaemon(True)
            d.start()
        self.shutdown(0,0)


    def proxy_thread(self, conn, client_addr):
        
        #NOTE guys : SYS module -> ssize_t recv(int sockfd, **** void *buf ***** (we use only this), size_t len, int flags); => this is a simple linux function

        #PART1: get the request from the client 
        # parse the url to get info on webserver , the port
        # if no port is specifies use the default 80

        request = conn.recv(config['MAX_REQUEST_LEN'])        # get the request from browser
        first_line = (request.split(b"\n")[0])       # parse the first line
        url = first_line.split(b' ')[1]                        # get url
                # Check if the host:port is blacklisted
        
        print(url)                       
        url = unquote(url)
        #print("3" + url)
        for i in range(0, len(config['BLACKLIST_DOMAINS'])):
            print("LOL" + str(i) +  config['BLACKLIST_DOMAINS'][i])
            if str(config['BLACKLIST_DOMAINS'][i]) in url:
                conn.close()
                print("Connection close for blocked Domain")
                print("1" + config['BLACKLIST_DOMAINS'][i])
                print("2" + url)
                return
        # find the webserver and port
        
        url = url.encode('utf8')
        http_pos = url.find(b"://")  # find pos of ://

        #print(http_pos) 

        if (http_pos==-1):
            temp = url
        else:
            temp = url[(http_pos+3):]       # get the rest of url
            print("reqd_url:",temp)

        port_pos = temp.find(b":")           # find the port pos (if any) =>returns -1 if none found
        print("port_pos:",port_pos)

        # find end of web server=> if / not found it is just set as length of the reqd_url
        webserver_pos = temp.find(b"/")
        if webserver_pos == -1:
            webserver_pos = len(temp)

        webserver = ""
        port = -1

        if (port_pos==-1 or webserver_pos < port_pos):      # default port
            port = 80
            webserver = temp[:webserver_pos]
        else:                                               # specific port
            port = int((temp[(port_pos+1):])[:webserver_pos-port_pos-1])
            webserver = temp[:port_pos]

        print("Final_web_server:",webserver,"Port:",port)


        

        try:
            # create a socket to connect to the web server
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            #s.settimeout(config['CONNECTION_TIMEOUT'])
            s.connect((webserver, port))                 #connecting to the server using url and port
            s.sendall(request)                           # send request to webserver

            while 1:
                data = s.recv(config['MAX_REQUEST_LEN'])    # receive data from web server as reply to request
                print(data)          
                if (len(data) > 0):
                    conn.send(data)                               # send to browser
                else:
                    break
            s.close()
            conn.close()
        except socket.error as error_msg:
            print ('ERROR: ',client_addr,error_msg)
            if s:
                s.close()
            if conn:
                conn.close()


    def _getClientName(self, cli_addr):
        """ Return the clientName.
        """
        return "Client"


    def shutdown(self, signum, frame):
        """ Handle the exiting server. Clean all traces """
        self.serverSocket.close()
        sys.exit(0)

if __name__ == "__main__":
    server = Server(config)
    server.listen_for_client()