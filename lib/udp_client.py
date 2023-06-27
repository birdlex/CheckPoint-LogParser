import socket

class UdpClient:
    def __init__(self, server_ip="127.0.0.1", server_port=6514):
        self.server_ip = server_ip
        self.server_port = server_port

    def send_message(self, message):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client_socket:
            client_socket.sendto(message.encode('utf-8'), (self.server_ip, self.server_port))

'''
# main.py
from udp_client import UdpClient

if __name__ == "__main__":
    udp_client = UdpClient(server_ip="127.0.0.1", server_port=8888)
    while True:
        user_input = input("Enter a message to send to the server (type 'exit' to quit): ")
        if user_input.lower() == 'exit':
            break

        udp_client.send_message(user_input)
'''