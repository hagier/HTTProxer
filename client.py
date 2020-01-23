#!/usr/bin/env python3
# -*- coding: utf-8 -*-
 
"""A short description of the module -- called a docstring."""
 
# Here comes your imports
import traceback
import socketserver
import signal
import socket
import threading
import sys
import base64
import requests
import uuid
import time
 
# Here comes your (few) global variables
BIND_ADDRESS = '127.0.0.1'
BIND_PORT = 9999

SERVER_ADDRESS = '127.0.0.1'
SERVER_PORT = 80

CLIENT_TIMEOUT = 60
 
# Here comes your class definitions
class ClientConnectionThread(threading.Thread):
    def __init__(self, client_socket, client_address):
        super(ClientConnectionThread, self).__init__()
        self.daemon = True
        self.flag_stop = False
        self.client_socket = client_socket
        self.client_address = client_address
        self.session_id = str(uuid.uuid1())
        print(f"Initiated ClientConnectionThread for {client_address}.")
         
    def run(self):
        print(f"Starting HTTP proxy between {self.client_address} and {SERVER_ADDRESS}:{SERVER_PORT}.")
        
        proxies = {
             "http": None,
             #"http": "http://localhost:8555",
             "https": None,
            }
            
        client_timeout = 0
        client_timestamp = time.time()
        
        session_request = requests.Session()
        session_request.headers.update({'Session-Id': self.session_id})
        while not self.flag_stop:
            try:   
                #time.sleep(1)
                received_from_local = self.socket_receive(self.client_socket)
                
                current_timestamp = time.time()
                proxy_response = None
                if received_from_local is None:
                    #if (current_timestamp-client_timestamp)/1.0 > client_timeout/CLIENT_TIMEOUT:
                    proxy_response = session_request.post(f"http://{SERVER_ADDRESS}:{SERVER_PORT}/", proxies = proxies)
                    if (current_timestamp-client_timestamp) > 1.0:
                        client_timeout += 1
                        client_timestamp = current_timestamp
                        #print(f"Update timestamp {client_timestamp}, count {client_timeout}.")
                else:
                    proxy_response = session_request.post(f"http://{SERVER_ADDRESS}:{SERVER_PORT}/", data=received_from_local, proxies = proxies)
                    client_timeout = 0
                    client_timestamp = current_timestamp
                  
                # Disconnect client who passed CLIENT_TIMEOUT variable value
                if client_timeout > CLIENT_TIMEOUT:
                    print(f"Client {self.client_address} disconnected. Timeout {CLIENT_TIMEOUT} seconds.")
                    break
                
                received_messages = None
                if proxy_response is not None:
                    received_messages = str(proxy_response.content, "utf8")
                    #print(f"Received: {proxy_response.content}")
                
                if received_messages is not None:
                    #print(f"Received message packet from PROXY: {received_messages}")
                    for message in received_messages.split(';'):
                        #print(f"Message from packet: {message}")
                        decoded_message = str(base64.b64decode(str(message)))
                        #print(f"DECODED: {decoded_message}")
                        self.socket_send(self.client_socket, message)
                
                
                #time.sleep(0.1)
                         
            except socket.timeout:
                print(f"Client disconnected.")
                break
            except requests.exceptions.ConnectionError:
                print(f"\n[ERROR] Could not connect to server {SERVER_ADDRESS}:{SERVER_PORT}\n")
                break
            except:
                traceback.print_exc()
                break
                    
                   
        self.client_socket.close()
        print('Stopping thread.')
        sys.exit(0)
        
    def socket_receive(self, socket_local):
        chunks = []
        bytes_recd = 0
        chunk = b''
        while b'\n' not in chunk:
            try:
                socket_local.settimeout(0.0)
                chunk = socket_local.recv(65000)
                if chunk == b'':
                    break
                chunks.append(chunk)
                bytes_recd = bytes_recd + len(chunk)
            except BlockingIOError:
                break
            except socket.timeout:
                pass
            except:
                traceback.print_exc()
                break
        
        data = b''.join(chunks)
        if data != b'':
            #print(f"\nReceived from local: {data}")
            data_encoded = base64.b64encode(data)
            return data_encoded
        return None
        
    def socket_send(self, socket, message):
        #print('Forwarding to ' + str(socket.getpeername()) + ' message: ' + str(message))
        if message != b'':
            message_decoded = base64.b64decode(message)
            #print('\nForwarding to ' + str(socket.getpeername()) + ' message: ' + str(message_decoded))
            socket.settimeout(5)
            socket.sendall(message_decoded)
 
class HTTProxerClient:

    def __init__(self):
        # Shutdown on Ctrl+C
        signal.signal(signal.SIGINT, self.shutdown) 
        
        # Create a TCP socket
        self.serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Re-use the socket
        self.serverSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # Bind the socket to a public host, and a port   
        print(f'Starting listener on {BIND_ADDRESS}:{BIND_PORT}....')
        self.serverSocket.bind((BIND_ADDRESS, BIND_PORT))
        self.serverSocket.listen(10) # become a server socket
        self.__clients = {}
        
        print("Listerner started. Awaiting connections...")
        
        while True:
            try:
                # Establish the connection
                self.serverSocket.settimeout(1)
                (client_socket, client_address) = self.serverSocket.accept() 
                
                print(f"Starting thread for {client_address}:{client_socket}.")

                #d = threading.Thread(name=self._getClientName(client_address), 
                connection_thread = ClientConnectionThread(client_socket = client_socket, client_address = client_address)
                connection_thread.start()
                print("Started")
            except socket.timeout:
                #print("Timeout")
                pass
            except e:
                traceback.print_exc()
                break
        
    def shutdown(self, signum, frame):
        """ Handle the exiting server. Clean all traces """
        print("Shutting down gracefully...")
        self.serverSocket.close()
        print("Próbuję wyjść...")
        sys.exit(0)
        
# Here comes your function definitions

def main():
    """Launcher."""
    print("Witaj w kliencie HTTProxer.")
    # init the GUI or anything else
    proxy = HTTProxerClient()
    pass
 
if __name__ == "__main__":
    main()