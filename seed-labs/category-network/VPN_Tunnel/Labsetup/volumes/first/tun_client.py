#!/usr/bin/env python3

import fcntl
import struct
import os
import socket
import time
from scapy.all import *

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

os.system("ip addr add 192.168.53.99/24 dev {}".format(ifname))
os.system("ip link set dev {} up".format(ifname))
os.system("ip route add 192.168.60.0/24 dev tun0 via 192.168.53.1")

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(('0.0.0.0', 9090))
while True:
    ready, _, _ = select.select([sock, tun], [], [])

    for fd in ready:
        if fd is tun:
            # Read from tun (packet going to the server)
            packet = os.read(tun, 2048)
            if packet:
                sock.sendto(packet, ("10.9.0.11", 9090))

        if fd is sock:
            # Read response from the server
            packet, _ = sock.recvfrom(2048)
            if packet:
                os.write(tun, packet)  # Inject back into TUN







