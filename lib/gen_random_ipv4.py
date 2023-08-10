import socket
import struct
import random
import os
from multiprocessing import Pool


def generate_ip():
  while True:
    ip = socket.inet_ntoa(struct.pack('>I', random.randint(1, 0xffffffff)))
    if is_valid(ip):
      return ip
    
def generate_ips(n):
  return [generate_ip() for _ in range(n)]


def is_valid(ip):
  # Avoid reserved IP address ranges
  reserved = [
      {"from": '0.0.0.0', "to": '0.255.255.255'},  # current network
      {"from": '10.0.0.0', "to": '10.255.255.255'},  # private network
      {"from": '100.64.0.0', "to": '100.127.255.255'},  # shared address space
      {"from": '127.0.0.0', "to": '127.255.255.255'},  # loopback
      {"from": '169.254.0.0', "to": '169.254.255.255'},  # link local
      {"from": '172.16.0.0', "to": '172.31.255.255'},  # private network
      {"from": '192.0.0.0', "to": '192.0.0.255'},  # ietf protocol assignments
      {"from": '192.0.2.0', "to": '192.0.2.255'},  # TEST-NET-1
      {"from": '192.88.99.0', "to": '192.88.99.255'},  # 6to4 relay anycase
      {"from": '192.168.0.0', "to": '192.168.255.255'},  # private network
      {"from": '198.18.0.0', "to": '198.19.255.255'},  # network interconnect device benchmark testin
      {"from": '198.51.100.0', "to": '198.51.100.255'},  # TEST-NET-2
      {"from": '203.0.113.0', "to": '203.0.113.255'},  # TEST-NET-3
      {"from": '224.0.0.0', "to": '239.255.255.255'},  # Multicast
      {"from": '240.0.0.0', "to": '255.255.255.255'}  # future use
  ]
  
  for network in reserved:
    if ip_to_int(ip) >= ip_to_int(network['from']) and ip_to_int(ip) <= ip_to_int(network['to']):
      return False
    
  return True


def ip_to_int(ip):
  return struct.unpack("!I", socket.inet_aton(ip))[0]


if __name__ == "__main__":
  num_processes = os.cpu_count()
  chunk_size = 1500000 // num_processes
  with Pool(num_processes) as p:
    ips_chunks = p.map(generate_ips, [chunk_size]*num_processes)
    
    # Flatten the list of lists
  ips = [ip for chunk in ips_chunks for ip in chunk]
  
  # Write to a file
  with open('/tmp/ip_list.txt', 'w') as f:
    for ip in ips:
      f.write(f'{ip}\n')
      