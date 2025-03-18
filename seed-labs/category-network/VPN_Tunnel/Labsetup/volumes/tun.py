#!/usr/bin/env python3

import fcntl
import struct
import os
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

while True:
    # Get a packet from the tun interface
    packet = os.read(tun, 2048)
    if packet:
        ip = IP(packet)
        print(ip.summary())  # Print IP packet details

        # Check if it's an ICMP echo request
        if ip.haslayer(ICMP) and ip[ICMP].type == 8:  # ICMP Echo Request
            print("ICMP Echo Request detected!")

            # Construct an Echo Reply packet
            new_ip = IP(src=ip.dst, dst=ip.src)
            new_icmp = ICMP(type=0)  # Echo Reply
            new_pkt = new_ip / new_icmp / ip[ICMP].payload
            os.write(tun, bytes(new_pkt))  # Write the reply back to the TUN interface
            print("Sending ICMP Echo Reply")

            random_data = b"HelloTUN"  # Arbitrary data
            os.write(tun, random_data)
            print("Sent arbitrary data to TUN interface.")





