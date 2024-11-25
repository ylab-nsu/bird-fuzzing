import socket
import time
from scapy.all import *
from scapy.all import IP
from bgp import *

def p_display(pkt):
    if IP in pkt:
        src_ip = pkt[IP].src  # Извлекаем IP-адрес источника
        print(f"Source IP: {src_ip}")
        if pkt[IP].src == '172.18.0.2':
            if str(pkt.summary()).find("BGPHeader") > 0:
                if pkt[BGPHeader].type == 1:
                    send(IP(dst=pkt[IP].src)/TCP(sport=pkt[TCP].dport, dport=pkt[TCP].sport, ack=pkt[TCP].seq + 1,seq=pkt[TCP].ack, flags="PA")/BGPHeader(type=1)/BGPOpen(version=4,AS=65002,hold_time=180,bgp_id='172.18.0.1'))
                    return "Open Message sent"
                elif pkt[BGPHeader].type == 2:
                    send(IP(dst=pkt[IP].src)/TCP(sport=pkt[TCP].dport, dport=pkt[TCP].sport, ack=pkt[TCP].seq + 1,seq=pkt[TCP].ack, flags="PA") / BGPHeader(type=4, len=19))
                    return "Update reply sent"
                elif pkt[BGPHeader].type == 3:
                    return "Notification Received"
                else:
                    # sending regular bgp keep_alive
                    send(IP(dst=pkt[IP].src) / TCP(sport=pkt[TCP].dport, dport=pkt[TCP].sport, ack=pkt[TCP].seq + 1,seq=pkt[TCP].ack, flags="PA") / BGPHeader(type=4, len=19))
                    return "Keep_alive sent"


# Запускаем захват пакетов в отдельном потоке
sniffer_thread = threading.Thread(target=lambda: sniff(iface='br-7895e720a1ae', prn=p_display, store=0))
sniffer_thread.start()

s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.bind(('172.18.0.1', 179))
s.listen(1)
conn, addr = s.accept()
print('Connected by', addr)

#closing off the connection
conn.close()
