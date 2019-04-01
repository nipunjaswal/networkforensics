#!/usr/bin/env python 
import subprocess 
import operator
import os
import math
import re
import schedule
import time
from prettytable import PrettyTable
def scan():
	proc = subprocess.Popen('iwlist wlan0 scan | grep -oE "(ESSID:|Address:|Channel:|Quality=).*" 2>/dev/null', shell=True, stdout=subprocess.PIPE, ) 
	stdout_str = proc.communicate()[0]
	stdout_list=stdout_str.split('\n')
	essid=[]
	address=[]
	channel=[]
	signal=[]
	decibel=[]
	distance=[]
	frequency=[]
	for line in stdout_list:
			line=line.strip() 
			match=re.search('ESSID:"(\S+)"',line) 
			if match: 
					essid.append(match.group(1)) 
			match=re.search('Channel:(\S*)',line) 
			if match: 
 					 channel.append(match.group(1))
					 frequency.append(int(match.group(1))*5 + 2407)
			match=re.search('Address:\s(\S+)',line)
			if match:
					 address.append(match.group(1))
			match=re.search('Signal level=(\S+)',line)
			if match:
					 signal.append(match.group(1))
					 decibel.append(abs(int(match.group(1))))
	i=0
	x = PrettyTable()
	x.field_names = ["ESSID", "MAC Address", "Channel", "Signal", "Distance","Frequency","Decibel"]
#	os.system("clear")
	while i < len(essid):
			distance= 10 ** ((27.55 - (20 * math.log10(int(frequency[i]))) + int(decibel[i]))/20)
			x.add_row([essid[i],address[i],channel[i],int(signal[i]),str(float(distance))+ " mtr",int(frequency[i]),int(decibel[i])])
			i=i+1
	print x.get_string(sort_key=operator.itemgetter(4, 0), sortby="Signal", reversesort=True)
	i=0
# Main Thread Starts
schedule.every(5).seconds.do(scan)
while 1:
    schedule.run_pending()
    time.sleep(1)
