from scapy.all import  *
import base64

network_packets = rdpcap('gnome.pcap')
decoded_commands = []
decoded_data =""
for packet in network_packets:
    if DNSQR in packet:
        if packet[DNS].id == 0x1337:
            decoded_data = base64.b64decode(str(packet[DNS].an.rdata))
	if 'FILE:' in decoded_data:
			continue
	else:
		decoded_commands.append(decoded_data)
for command in decoded_commands:
	if len(command)>1:
		print command.rstrip()
