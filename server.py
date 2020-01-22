#!/usr/bin/env python3
# -*- coding: utf-8 -*-
 
"""A short description of the module -- called a docstring."""
 
# Here comes your imports
import http.server
import socketserver
import signal
import sys
import threading
import socket
import base64
import time
import uuid
import traceback

# Here comes your (few) global variables
BIND_ADDRESS = '0.0.0.0'
BIND_PORT = 8080

REMOTE_ADDRESS = '127.0.0.1'
REMOTE_PORT = 22

class ServerConnectionThread(threading.Thread):
    #incoming_message = []
    outgoing_messages = []

    def __init__(self, name):
        super(ServerConnectionThread, self).__init__()
        self.daemon = True
        self.name = name
        self.flag_stop = False
        self.socket_remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print(f"Connecting thread {self.name} to remote port {REMOTE_ADDRESS}:{REMOTE_PORT}...")
        self.socket_remote.connect((REMOTE_ADDRESS, REMOTE_PORT))
        print(f"Connected to {REMOTE_ADDRESS}:{REMOTE_PORT}.")
        
    def run(self):
        while not self.flag_stop:
            data_received = self._socket_receive(self.socket_remote)
            if data_received != b'':
                print(f"\nAdding message from socket [{data_received}] to outgoing messages.")
                self.outgoing_messages.append(str(base64.b64encode(data_received), "utf8"))
                continue
            time.sleep(0.1)            
        
        print(f"End of thread {self.name}.")
        
    def stop(self):
        self.flag_stop = True
        self.socket_remote.close()
        
    def send_message(self, message):
        data = base64.b64decode(message)
        self._socket_send(self.socket_remote, data)
        
    def receive_messages(self):
        if len(self.outgoing_messages) > 1:
            print("Joining outgoing messages...")
            messages = ';'.join(self.outgoing_messages)
        elif len(self.outgoing_messages) == 1:
            print("Joining 111111111 outgoing messages...")
            messages = self.outgoing_messages[0]
        else:
            messages = ""
        self.outgoing_messages = []        
        return messages
        
        
    def _socket_receive(self, socket_remote):
        chunks = []
        bytes_recd = 0
        chunk = b''
        
        while b'\n' not in chunk:
            try:
                socket_remote.settimeout(0.0)
                chunk = socket_remote.recv(65000)
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
        return b''.join(chunks)
        
    def _socket_send(self, socket_remote, message):
        #if message != b'KEEP_ALIVE':
        socket_remote.sendall(message)
        
 
# Here comes your class definitions
class HTTProxerRequestHandler(http.server.BaseHTTPRequestHandler):
    def _set_headers(self, code = 200):
        self.send_response(code)
        self.send_header("Content-type", "text/html")
        self.end_headers()
    
    def version_string(self):
        return "Unknown"

    def _html(self, message):
        """This just generates an HTML document that includes `message`
        in the body. Override, or re-write this do do more interesting stuff.
        """
        content = f"{message}"
        return content.encode("utf8")  # NOTE: must return a bytes object!
        
    def send_head():
        """Empty"""
        
    def set_socket_remote(self, socket_to_assign):
        self.socket_remote = socket_to_assign
        
    def response_fake(self):
        self._set_headers(500)
        self.wfile.write(self._html("Service unavailable. Thread: " + threading.currentThread().getName() + "\n"))

    def do_GET(self):
        self.response_fake()

    def do_HEAD(self):
        self.response_fake()

    def do_POST(self):               
        #time.sleep(1)
        if self.headers["Session-Id"] is None:
            self.response_fake()
            return
            
        request_data = self.rfile.read(int(self.headers.get('content-length')))
            
        request_data_decoded = base64.b64decode(request_data)
        print(f"\nRequest data: {request_data}. Decoded: {request_data_decoded}.")
        
        connection_thread = self.find_thread(self.headers["Session-Id"])
        connection_thread.send_message(request_data)
            
        #print("Showing threads before find:", threading.enumerate())
        #print("Result of thread search: ", self.find_thread(self.headers["Session-Id"]))
        #print("Showing threads after find:", threading.enumerate())
        #print("Client session ID: " + str(self.headers["Session-Id"]))
        
        try:
            # Send HTTP response
            self._set_headers()
            messages_to_send = connection_thread.receive_messages()
            print(f"Sending full response: {messages_to_send}")
            self.wfile.write(self._html(messages_to_send))
        except:
            traceback.print_exc()
            pass    
        
    # Returns thread if found (based on name) or None if there's no .
    def find_thread(self, thread_name):
        # Look for thread with name equal to thread_name
        for thread in threading.enumerate():
            if thread.name == thread_name:
                print(f"Found thread named {thread_name}! Not starting new thread")
                return thread
        # If not found, create a new thread
        print(f"Thread named {thread_name} not found. Starting new thread")
        thread_new = ServerConnectionThread(thread_name)
        thread_new.start()
        return thread_new
        
class HTTProxerServer:
    def __init__(self):
        # Shutdown on Ctrl+C
        signal.signal(signal.SIGINT, self.shutdown)
                                
        self.start_http1_server()
        
    def start_http1_server(self):
        print("Initializing HTTP1 server.")
        http1_handler = HTTProxerRequestHandler

        with http.server.ThreadingHTTPServer((BIND_ADDRESS, BIND_PORT), http1_handler) as httpd:
            print(f"Server started at {BIND_ADDRESS}:{BIND_PORT}.")
            httpd.serve_forever()
            
    def start_http2_server(self):
        print(f"Initializing HTTP2 server on {BIND_ADDRESS}:{BIND_PORT}.")
        
    def thread_test(self):
        while True:
            """nothing"""
            
    def shutdown(self, signum, frame):
        print("Exiting...")
        sys.exit(0)
        
        
        
 
# Here comes your function definitions
def main():
    """Launcher."""    
    print("Starting HTTProxer server...")
    # init the GUI or anything else
    proxy = HTTProxerServer()
    pass
 
if __name__ == "__main__":
    main()