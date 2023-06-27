import socket

class TcpConfigClient:
    def __init__(self, server_ip="127.0.0.1", server_port=8888):
        self.server_ip = server_ip
        self.server_port = server_port

    def send_message(self, message):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.connect((self.server_ip, self.server_port))
            client_socket.sendall(message.encode('utf-8'))


