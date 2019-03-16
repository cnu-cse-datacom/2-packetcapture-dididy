import socket
import struct
import time

def parsing_ethernet_header(data):
  ethernet_header = struct.unpack("!6c6c2s", data)
  ether_src = convert_ethernet_address(ethernet_header[0:6])
  ether_dest = convert_ethernet_address(ethernet_header[6:12])
  ip_header = "0x"+ethernet_header[12].hex()
  print("------------------------------------------------------")
  print("=====ethernet header=====")
  print("| src_mac_address:", ether_src)
  print("| dest_mac_address:", ether_dest)
  print("| ip_version", ip_header)

def convert_ethernet_address(data):
  ethernet_addr = list()
  for i in data:
    ethernet_addr.append(i.hex())
  ethernet_addr = ":".join(ethernet_addr)
  return ethernet_addr

def parsing_ip_header(data):
  ip_header = struct.unpack("!1c1c2s2s2s1c1c2s4c4c", data)
  print("------------------------------------------------------")
  print("=====ip header=====")
  print("| ip_version ->",  int(ip_header[0].hex()[0], 16))
  print("| ip_length ->", int(ip_header[0].hex()[1], 16))
  print("| differentiated_services ->", ip_header[1].hex()[0])
  print("| explicit_services_codepoint ->",  ip_header[1].hex()[1])
  print("| total_length ->", int(ip_header[2].hex(), 16))
  print("| identification ->", int(ip_header[3].hex(), 16))
  print("| flags ->", "0x" + ip_header[4].hex())
  ##
  print("| >> reserved_bit ->", ip_header[4].hex()[0])
  print("| >> dont_fragment ->", ip_header[4].hex()[1])
  print("| >> more_fragments ->", ip_header[4].hex()[2])
  print("| >> fragments_offset ->", ip_header[4].hex()[3])
  ##
  print("| timetolive ->", int(ip_header[5].hex(), 16))
  print("| protocol ->", int(ip_header[6].hex(), 16))
  print("| header_checksum ->", "0x" + ip_header[7].hex())
  print("| source_ip ->", convert_ip_address(ip_header[8:12]))
  print("| dest_ip ->", convert_ip_address(ip_header[12:16]))
  return int(ip_header[6].hex(), 16)

def convert_ip_address(data):
  ip_address = list()
  for i in data:
    ip_address.append(str(int(i.hex(), 16)))
  ip_address = ".".join(ip_address)
  return ip_address

def parsing_tcp_header(data):
  tcp_header = struct.unpack("!2s2s4s4s2s2s2s2s", data)
  slicing = bin(int(tcp_header[4].hex(), 16))
  slicing = slicing[2:18]
  print("------------------------------------------------------")
  print("=====tcp header=====")
  print("| source_port ->", int(tcp_header[0].hex(), 16))
  print("| destination_port ->", int(tcp_header[1].hex(), 16))
  print("| sequence_number ->", int(tcp_header[2].hex(), 16))
  print("| acknowledge_number ->", int(tcp_header[3].hex(), 16))
  print("| header_length ->", int(tcp_header[4].hex()[0], 16))
  print("| flags ->", int(tcp_header[4].hex()[1:4], 16))
  print("| >> reserved ->", int(slicing[4:6], 2)) 
  print("| >> nonce ->", int(slicing[7], 2))
  print("| >> cwr ->", int(slicing[8], 2))
  print("| >> ecr ->", int(slicing[9], 2))
  print("| >> urgent ->", int(slicing[10], 2))
  print("| >> ack ->", int(slicing[11], 2))
  print("| >> push ->", int(slicing[12], 2))
  print("| >> reset ->", int(slicing[13], 2))
  print("| >> syn ->", int(slicing[14], 2))
  print("| >> fin ->", int(slicing[15], 2))
  print("| window_size_value ->", int(tcp_header[5].hex(), 16))
  print("| checksum ->", int(tcp_header[6].hex(), 16))
  print("| urgent_pointer ->", int(tcp_header[7].hex(), 16))

def parsing_udp_header(data):
  udp_header = struct.unpack("!2s2s2s2s", data)
  print("------------------------------------------------------")
  print("=====udp header=====")
  print("| source_port ->", int(udp_header[0].hex(), 16))
  print("| destination_port ->", int(udp_header[1].hex(), 16))
  print("| length ->", int(udp_header[2].hex(), 16))
  print("| checksum ->", int(udp_header[3].hex(), 16))

recv_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x800))
i = 0

while True:
  print("* * * * * * * * * * * * * * * * * * * * * * * * * * *")
  print("No.{0} packet".format(i))
  data = recv_socket.recvfrom(20000)
  parsing_ethernet_header(data[0][0:14])
  protocol_branch = parsing_ip_header(data[0][14:34])
  if(protocol_branch == 6):
    parsing_tcp_header(data[0][34:54])
  elif(protocol_branch == 17):
    parsing_udp_header(data[0][34:42])
  print("* * * * * * * * * * * * * * * * * * * * * * * * * * *")
  time.sleep(10)
  i = i + 1 
  print("")
