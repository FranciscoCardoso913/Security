#!/usr/bin/env python3
from scapy.all import *
import fcntl
import struct
import os
IP_A = "0.0.0.0"
PORT = 9090
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((IP_A, PORT))

TUNSETIFF = 0x400454ca
IFF_TUN   = 0x0001
IFF_TAP   = 0x0002
IFF_NO_PI = 0x1000

# Create the tun interface
tun = os.open("/dev/net/tun", os.O_RDWR)
ifr = struct.pack('16sH', b'tun%d', IFF_TUN | IFF_NO_PI)
ifname_bytes  = fcntl.ioctl(tun, TUNSETIFF, ifr)

# Get the interface name
ifname = ifname_bytes.decode('UTF-8')[:16].strip("\x00")
print("Interface Name: {}".format(ifname))

os.system("ip addr add 192.168.54.99/24 dev {}".format(ifname))
os.system("ip link set dev {} up".format(ifname))
os.system("ip route add 192.168.50.0/24 dev tun0 via 192.168.54.1")
# We assume that sock and tun file descriptors have already been created.
client_ip = '10.9.0.12'
client_port = 9090
while True:
	ready, _, _ = select.select([sock, tun], [], [])
	for fd in ready:
		if fd is sock:
			# Read from socket (packets from client)
			data, (client_ip, client_port) = sock.recvfrom(2048)
			pkt = IP(data)
			print("From socket <==: {} --> {}".format(pkt.src, pkt.dst))
			# Inject into TUN interface (send to Host V)
			os.write(tun, bytes(pkt))

		if fd is tun:
			# Read from TUN (response from Host V)
			packet = os.read(tun, 2048)
			pkt = IP(packet)
			print("From tun ==>: {} --> {}".format(pkt.src, pkt.dst))
			# Send back to the client over the socket
			sock.sendto(bytes(pkt), (client_ip, client_port))