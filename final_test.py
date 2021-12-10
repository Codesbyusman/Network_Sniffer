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
# your code goes here.............

config = {
            "HOST_NAME": "127.0.0.1",
            "BIND_PORT": 8000,
            "MAX_REQUEST_LEN": 4096,
            "CONNECTION_TIMEOUT": 10,
            "BLACKLIST_DOMAINS": ["http://testasp.vulnweb.com/", "http://testasp.vulnweb.com/"],
            "REDIRECT_DOMAINS": ["http://testphp.vulnweb.com/", "http://testphp.vulnweb.com/"]
          }


class Server:
    """ The server class """
    # PART1: Creating a socket for the server
    # We will now do it in a function
    # and to listene to a max of 10 clients at a time

    def __init__(self, config):

        signal.signal(signal.SIGINT, self.shutdown)     # Shutdown on Ctrl+C
        self.serverSocket = socket.socket(
            socket.AF_INET, socket.SOCK_STREAM)             # Create a TCP socket
        self.serverSocket.setsockopt(
            socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)    # Re-use the socket
        # bind the socket to a public host, and a port
        self.serverSocket.bind((config['HOST_NAME'], config['BIND_PORT']))
        self.serverSocket.listen(10)    # become a server socket
        self.__clients = {}

    def listen_for_client(self):
        """ Wait for clients to connect """
        # PART 2:LISTEN FOR CLIENT We wait for the clients connection request and once a
        # successful connection is made we dispatch the request in a separate thread,
        # making ourselves available for the next request.
        # This allows us to handle multiple requests simultaneously which boosts the performance of the
        # server multifold times. -> we need a function for threading and to get client name!!!

        while True:
            # Establish the connection
            (clientSocket, client_address) = self.serverSocket.accept()

            d = threading.Thread(name=self._getClientName(
                client_address), target=self.proxy_thread, args=(clientSocket, client_address))
            d.setDaemon(True)
            d.start()
        self.shutdown(0, 0)

    def proxy_thread(self, conn, client_addr):

        # NOTE guys : SYS module -> ssize_t recv(int sockfd, **** void *buf ***** (we use only this), size_t len, int flags); => this is a simple linux function

        # PART1: get the request from the client
        # parse the url to get info on webserver , the port
        # if no port is specifies use the default 80

        # get the request from browser
        request = conn.recv(config['MAX_REQUEST_LEN'])
        first_line = (request.split(b"\n")[0])       # parse the first line
        url = first_line.split(b' ')[1]                        # get url
                # Check if the host:port is blacklisted

        print(url)
        url = unquote(url)
        print("3" + url)
        for i in range(0, len(config['BLACKLIST_DOMAINS'])):
            print("LOL" + str(i) + config['BLACKLIST_DOMAINS'][i])
            if str(config['BLACKLIST_DOMAINS'][i]) in url:
                conn.close()
                print("Connection close for blocked Domain")
                print("1" + config['BLACKLIST_DOMAINS'][i])
                print("2" + url)
                return

        
        redirect=False          
        for i in range(0, len(config['REDIRECT_DOMAINS'])):
            print("LOL" + str(i) +  config['REDIRECT_DOMAINS'][i])
            if str(config['REDIRECT_DOMAINS'][i]) in url:
                #conn.close()
                print("REdirecting to the main domain")
                print("1" + config['REDIRECT_DOMAINS'][i])
                print("2" + url)
                redirect=True
                
        # find the webserver and port
        
        url = url.encode('utf8')
        http_pos = url.find(b"://")  # find pos of ://
	
        print(http_pos) 

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
	
        if(redirect):
            webserver="nu.edu.pk"
        

        try:
            # create a socket to connect to the web server
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # s.settimeout(config['CONNECTION_TIMEOUT'])
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

