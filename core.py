import socket
import struct

def parsing_ethernet_header(data):
  ethernet_header = struct.unpack("!6c6c2s", data)
  ether_src = convert_ethernet_address(ethernet_header[0:6])
  ether_dest = convert_ethernet_address(ethernet_header[6:12])
  ip_header = "0x"+ethernet_header[12].hex()

  print("=====ethernet header=====")
  print("src_mac_address:", ether_src)
  print("dest_mac_address:", ether_dest)
  print("ip_version", ip_header)
  print(ethernet_header)
def convert_ethernet_address(data):
  ethernet_addr = list()
  for i in data:
    ethernet_addr.append(i.hex())
  ethernet_addr = ":".join(ethernet_addr)
  return ethernet_addr

def parsing_ip_header(data):
  ip_header = struct.unpack("1c1c2s2s2s1c1c2s4c4c", data)
  ip_version = int(ip_header[0].hex()[0], 16)
  ip_length = int(ip_header[0].hex()[1], 16)
  differentiated_services = ip_header[1].hex()[0]
  explicit_services_codepoint = ip_header[1].hex()[1]
  total_length = int(ip_header[2].hex(), 16)
  flags = "0x" + ip_header[4].hex()
  timetolive = int(ip_header[5].hex()[0], 16)
  protocol = int(ip_header[5].hex()[1], 16)


  print(ip_version)
  print(ip_length)
  print(differentiated_services)
  print(explicit_services_codepoint)
  print(total_length)
  print(flags)
  print(timetolive)
  print(protocol)
recv_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x800))

print("<<<<<<<<<<Packet Capture Start>>>>>>>>>>")

  
data = recv_socket.recvfrom(20000)
parsing_ethernet_header(data[0][0:14])
parsing_ip_header(data[0][14:34])
