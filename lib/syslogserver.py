import socket
import threading
import socketserver

class ThreadedUDPRequestHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        cur_thread = threading.current_thread()
        response = bytes(
            "{}: {}".format(cur_thread.name, data.decode("ascii")), "ascii"
        )
        sock.sendto(response, self.client_address)


class ThreadedUDPServer(socketserver.ThreadingMixIn, socketserver.UDPServer):
    pass

class ThreadedTCPRequestHandler(socketserver.BaseRequestHandler):

    def handle(self):
        data = str(self.request.recv(1024), 'ascii')
        cur_thread = threading.current_thread()
        response = bytes("{}: {}".format(cur_thread.name, data), 'ascii')
        self.request.sendall(response)

class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass