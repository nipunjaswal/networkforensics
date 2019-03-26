#!/usr/bin/python
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from collections import defaultdict
from cStringIO import StringIO
from struct import unpack
import re
import json
from datetime import datetime
import argparse
import os
import sys
from aplib import Decompress

packet_queue = defaultdict(list)
parsed_payload={}
parsed_payload['Network'] = {}
#parsed_payload['Compromised Host/User Description'] = {}
#parsed_payload['Compromised Host/User Data'] = {}
parsed_payload['Malware Artifacts/IOCs'] = {}

def format_header(unformatted_http_header):
	http_header_dict = {}
	split_http_header = unformatted_http_header.split('\r\n')

	if split_http_header[0].startswith('POST '):
		method, URI, HTTPVersion = split_http_header.pop(0).split(' ')

	http_header_dict['HTTP-Method'] = method
	http_header_dict['HTTP-URI'] = URI
	http_header_dict['HTTP-Version'] = HTTPVersion

	for header in split_http_header:
		if ":" in header:
			key, value = header.split(': ',1)
			http_header_dict[key] = value

	return http_header_dict	
def getString(stream):
	wide = unpack("h", stream.read(2))[0]
	length = unpack("i", stream.read(4))[0]
	if wide == 0:
		return ''.join(unpack("s"*length, stream.read(length)))
	else:
		return ''.join(map(chr,unpack("h"*(length/2), stream.read(length))))
			
def ifthesessioniscompleted(packet):
	packet_key_name = '%s:%s --> %s' % (packet[IP].src,packet[IP].sport, packet[IP].dst)
        packet_queue[packet_key_name].append(packet)
        for session in packet_queue:
                SYN     = False
                PSH_ACK = False
                ACK_FIN = False
		PSH_ACK_FIN = False

                for session_packet in packet_queue[session]:
                        if session_packet[TCP].flags == 2:
                                #print 'SYN found'
                                SYN = True
                        if session_packet[TCP].flags == 24:
                                #print 'PSH_ACK found'
                                PSH_ACK = True
                        if session_packet[TCP].flags == 17:
                                #print 'ACK_FIN found'
                                ACK_FIN = True
			if session_packet[TCP].flags == 25:
				#print 'PSH_ACK_FIN found'
				PSH_ACK_FIN = True

                if (SYN and PSH_ACK and ACK_FIN) or PSH_ACK_FIN:
			return True
	return False

def isLokiBotTraffic(http_headers):
	indicator_count = 0
	content_key_pattern = re.compile("^([A-Z0-9]{8}$)")

	if 'User-Agent' in http_headers and http_headers['User-Agent'] == 'Mozilla/4.08 (Charon; Inferno)':
		return True

	if 'HTTP-Method' in http_headers and http_headers['HTTP-Method'] == 'POST':
		indicator_count += 1

	if all(key in http_headers for key in ('User-Agent','Host','Accept','Content-Type','Content-Encoding', 'Content-Key')):
		indicator_count +=1

	if 'User-Agent' in http_headers and any(UAS_String in http_headers['User-Agent'] for UAS_String in ('Charon','Inferno')):
		indicator_count +=1

	if 'Content-Key' in http_headers and content_key_pattern.match(http_headers['Content-Key']):
		indicator_count +=1

	if indicator_count >= 3:
		return True
	else:
		return False

def extractHeaderAndPayload(full_session):
	http_header = {}
	http_payload = StringIO()
	
	for packet in full_session:
		if packet[TCP].flags in (24,25) :
			if packet[TCP].load.startswith('POST '):
				http_header = format_header(packet[TCP].load)
			else:
				if Padding in packet:
					http_payload = StringIO(packet[TCP].load + packet[Padding].load)
				else:
					http_payload = StringIO(packet[TCP].load)
	return http_header,http_payload	
def investigate_packets(packet):
	pack__name = '%s:%s --> %s' % (packet[IP].src,packet[IP].sport, packet[IP].dst)
#	print pack__name
	if ifthesessioniscompleted(packet):
                http_header, http_data = extractHeaderAndPayload(packet_queue[pack__name])
		if isLokiBotTraffic(http_header):
			parsed_payload['Network'].update({'Source IP': packet[IP].src})
			parsed_payload['Network'].update({'Source Port': packet[IP].sport})
			parsed_payload['Network'].update({'Destination IP': packet[IP].dst})
			parsed_payload['Network'].update({'Destination Port': packet[IP].dport})
			parsed_payload['Network'].update({'HTTP URI': http_header['HTTP-URI']})
			parsed_payload['Malware Artifacts/IOCs'].update({'HTTP Method': http_header['HTTP-Method']})		
			parsed_payload['Malware Artifacts/IOCs'].update({'Key Value': http_header['Content-Key']})
			parsed_payload['Network'].update({'Destination Host': http_header['Host']})
			parsed_payload['Network'].update({'Data Transmission Time': datetime.fromtimestamp(packet.time).isoformat()})
			parsed_payload['Malware Artifacts/IOCs'].update({'User-Agent String': http_header['User-Agent']})
			print parsed_payload
			#parse_lokibot_payload(http_payload)
			#print json.dumps(parsed_payload,ensure_ascii=False,sort_keys=True, indent=4)
			#print_to_file(parsed_payload)
			parsed_payload['Network'].clear()
#			parsed_payload['Compromised Host/User Description'].clear()
#			parsed_payload['Compromised Host/User Data'].clear()
			parsed_payload['Malware Artifacts/IOCs'].clear()
		del packet_queue[pack__name]


packets = rdpcap("loki-bot_network_traffic.pcap")
for packet in packets:
    if TCP in packet:
        investigate_packets(packet)
