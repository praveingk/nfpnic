from scapy.all import *

sport = random.randint(1024,65535)

# SYN
eth = Ether()
ip=IP(src='172.16.120.5',dst='172.16.100.101')
SYN=TCP(sport=sport,dport=443,flags='S',seq=1002)

sendp(eth/ip/SYN, iface="vf0_0")

DATA=TCP(sport=sport,dport=443,seq=1003)
sendp(eth/ip/DATA, iface="vf0_0")

sendp(eth/ip/DATA, iface="vf0_0")


# ACK
ACK=TCP(sport=sport, dport=443, flags='A', seq=1001, ack = 1001)
sendp(eth/ip/ACK, iface="vf0_0")

MOACK=TCP(sport=sport, dport=443, flags='A', seq=1000, ack = 900)
sendp(eth/ip/MOACK, iface="vf0_0")
