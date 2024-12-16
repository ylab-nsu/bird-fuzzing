import json
import socket
import time
import threading
from scapy.all import *
from scapy.all import IP
from bgp import *

# loading configuration from file
with open('config.json') as config_file:
    config = json.load(config_file)

# getting parameters from config
BIRD_CON_NAME = config["BIRD_CON_NAME"]
BGP_PROTO_NAME = config["BGP_PROTO_NAME"]
BIRD_ASN_ID = config["BIRD_ASN_ID"]
HOST_BGP_ID = config["HOST_BGP_ID"]
PARAM_HOLD_TIME = config["PARAM_HOLD_TIME"]
BIRD_BGP_ID = config["BIRD_BGP_ID"]
BIRD_BGP_PORT = config["BIRD_BGP_PORT"]

def p_display(pkt):
    if IP in pkt:
        src_ip = pkt[IP].src  # getting source's IP-address 
        if pkt[IP].src == BIRD_BGP_ID:
            if str(pkt.summary()).find("BGPHeader") > 0:
                if pkt[BGPHeader].type == 1:
                    send(IP(dst=pkt[IP].src)/TCP(sport=pkt[TCP].dport, dport=pkt[TCP].sport, ack=pkt[TCP].seq + 1, seq=pkt[TCP].ack, flags="PA")/BGPHeader(type=1)/BGPOpen(version=4, AS=BIRD_ASN_ID, hold_time=PARAM_HOLD_TIME, bgp_id=HOST_BGP_ID))
                    return "Open Message sent"
                elif pkt[BGPHeader].type == 2:
                    send(IP(dst=pkt[IP].src)/TCP(sport=pkt[TCP].dport, dport=pkt[TCP].sport, ack=pkt[TCP].seq + 1, seq=pkt[TCP].ack, flags="PA") / BGPHeader(type=4, len=19))
                    return "Update reply sent"
                elif pkt[BGPHeader].type == 3:
                    return "Notification Received"
                else:
                    # sending regular bgp keep_alive
                    send(IP(dst=pkt[IP].src) / TCP(sport=pkt[TCP].dport, dport=pkt[TCP].sport, ack=pkt[TCP].seq + 1, seq=pkt[TCP].ack, flags="PA") / BGPHeader(type=4, len=19))
                    return "Keep_alive sent"

# Start sniffing packets
sniffer_thread = threading.Thread(target=lambda: sniff(iface='br-7895e720a1ae', prn=p_display, store=0))
sniffer_thread.start()

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((HOST_BGP_ID, BIRD_BGP_PORT))
s.listen(1)
conn, addr = s.accept()
print('Connected by', addr)

# closing off the connection
conn.close()
