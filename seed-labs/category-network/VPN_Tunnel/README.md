# VPN Tunneling Lab

3.1
```
11: tun0: <POINTOPOINT,MULTICAST,NOARP> mtu 1500 qdisc noop state DOWN group default qlen 500
    link/none 

```

```
12: cardoso0: <POINTOPOINT,MULTICAST,NOARP> mtu 1500 qdisc noop state DOWN group default qlen 500
    link/none 

```
3.2
```
14: tun0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UNKNOWN group default qlen 500
    link/none 
    inet 192.168.53.99/24 scope global tun0
       valid_lft forever preferred_lft forever
    inet6 fe80::1c21:efa2:edf9:5d86/64 scope link stable-privacy 
       valid_lft forever preferred_lft forever
```
3.3
```
IP / ICMP 192.168.53.99 > 192.168.53.2 echo-request 0 / Raw
IP / ICMP 192.168.53.99 > 192.168.53.2 echo-request 0 / Raw

```

3.4

```
IP / ICMP 192.168.53.99 > 192.168.53.2 echo-request 0 / Raw
ICMP Echo Request detected!
Sending ICMP Echo Reply

```
tcpdump -i tun0
```
23:30:07.133276 IP 192.168.53.99 > 192.168.53.50: ICMP echo request, id 22, seq 7, length 64
23:30:07.134382 IP 192.168.53.50 > 192.168.53.99: ICMP echo reply, id 0, seq 0, length 64
23:30:07.134408 IP [|ip]

```

4.1

```py
# tun_server
#!/usr/bin/env python3
from scapy.all import *
IP_A = "0.0.0.0"
PORT = 9090
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((IP_A, PORT))
while True:
	data, (ip, port) = sock.recvfrom(2048)
	print("{}:{} --> {}:{}".format(ip, port, IP_A, PORT))
	pkt = IP(data)
	print(" Inside: {} --> {}".format(pkt.src, pkt.dst))
	send(pkt)
```

```
10.9.0.5:38143 --> 0.0.0.0:9090
Inside: 192.168.53.99 --> 192.168.53.1

```
```
ip route add 192.168.60.0/24 dev tun0 via 192.168.53.1
```

```
Sent 1 packets.
10.9.0.5:48127 --> 0.0.0.0:9090
 Inside: 192.168.53.99 --> 192.168.60.5

```

```
# tcpdump -i eth0 icmp
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on eth0, link-type EN10MB (Ethernet), capture size 262144 bytes
14:59:26.159326 IP 192.168.53.99 > 40cf349a63a2: ICMP echo request, id 12, seq 420, length 64
14:59:26.159344 IP 40cf349a63a2 > 192.168.53.99: ICMP echo reply, id 12, seq 420, length 64

```

5

```
10.9.0.5:44447 --> 0.0.0.0:9090
 Inside: 192.168.53.99 --> 192.168.60.5

```
```
tcpdump -i eth0 icmp
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on eth0, link-type EN10MB (Ethernet), capture size 262144 bytes
15:44:21.922083 IP 192.168.53.99 > 7082b0f8e861: ICMP echo request, id 22, seq 9, length 64
15:44:21.922102 IP 7082b0f8e861 > 192.168.53.99: ICMP echo reply, id 22, seq 9, length 64
```

6

```py
# tun_client.py
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

```

```py
#tun_server.py
client_ip = '0.0.0.0'
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

```

```
ping 192.168.60.5
PING 192.168.60.5 (192.168.60.5) 56(84) bytes of data.
64 bytes from 192.168.60.5: icmp_seq=1 ttl=63 time=1.80 ms
64 bytes from 192.168.60.5: icmp_seq=2 ttl=63 time=1.47 ms
64 bytes from 192.168.60.5: icmp_seq=3 ttl=63 time=1.38 ms

```

```
./tun_server.py 
Interface Name: tun0
From tun ==>: 0.0.0.0 --> 137.252.253.197
From socket <==: 0.0.0.0 --> 137.252.253.197
From socket <==: 0.0.0.0 --> 137.160.243.175
From tun ==>: 0.0.0.0 --> 137.252.253.197
From socket <==: 192.168.53.99 --> 192.168.60.5
From tun ==>: 192.168.60.5 --> 192.168.53.99
From socket <==: 192.168.53.99 --> 192.168.60.5
From tun ==>: 192.168.60.5 --> 192.168.53.99

```

```
tcpdump -i tun0 icmp
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on tun0, link-type RAW (Raw IP), capture size 262144 bytes
19:31:35.804872 IP 192.168.53.99 > 192.168.60.5: ICMP echo request, id 30, seq 55, length 64
19:31:35.806485 IP 192.168.60.5 > 192.168.53.99: ICMP echo reply, id 30, seq 55, length 64
```

7
from client vpn
```
From tun ==>: 192.168.50.5 --> 192.168.60.5
From socket <==: 192.168.60.5 --> 192.168.50.5

```

from server vpn 
```
From socket <==: 192.168.50.5 --> 192.168.60.5
From tun ==>: 192.168.60.5 --> 192.168.50.5

```

from host U

```
ping 192.168.60.5
PING 192.168.60.5 (192.168.60.5) 56(84) bytes of data.
64 bytes from 192.168.60.5: icmp_seq=957 ttl=62 time=1.48 ms
64 bytes from 192.168.60.5: icmp_seq=958 ttl=62 time=1.53 ms

```