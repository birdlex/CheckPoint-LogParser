import socket
import threading
import sys

class TcpConfigServer:
    def __init__(self, port=8888):
        self.port = port
        self.stop_event = threading.Event()

    def handle_log_tcp_config(self, conn, addr):
        print(f"Connection from {addr}", file=sys.stdout)
        # print('This is standard output', file=sys.stdout)

        while True:
            data = conn.recv(1024)
            if not data:
                break

            print(f"Received data from {addr}: {data.decode('utf-8')}", file=sys.stdout)
            sys.stdout.flush()

        print(f"Closing connection with {addr}", file=sys.stdout)
        conn.close()

    def config_server(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(('0.0.0.0', self.port))
        server.listen()

        print(f'Starting TCP config_server on {server.getsockname()}', file=sys.stdout)

        while not self.stop_event.is_set():
            conn, addr = server.accept()
            client_thread = threading.Thread(target=self.handle_log_tcp_config, args=(conn, addr))
            client_thread.start()

    def start(self):
        try:
            self.config_server()
        except KeyboardInterrupt:
            self.stop_event.set()

