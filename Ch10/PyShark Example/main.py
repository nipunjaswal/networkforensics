import pyshark
import struct

cap = pyshark.FileCapture(r'C:\Users\Apex\Desktop\ab.pcap')
def Exfil(pkt):
    try:
        if pkt.http.request_method == "POST":
            if pkt.http.user_agent == "Mozilla/4.08 (Charon; Inferno)":
                print "Infected IP:" + pkt.ip.src
                print "Communicating From:" + pkt[pkt.transport_layer].srcport
                print "Malicious HTTP Request:" + pkt.http.request_uri
                print "Malicious User-Agent" + pkt.http.user_agent
                print "C2 Server:" + pkt.ip.dst
                print "Time:" + str(pkt.sniff_time)
                Reason = pkt.http.data[4:6]
                if Reason == "27":
                    print "Traffic Purpose: Exfiltrate Application/Credential Data"
                elif Reason == "28":
                    print "Traffic Purpose: Get C2 Commands"
                elif Reason == "2b":
                    print "Traffic Purpose': Exfiltrate Keylogger Data"
                elif Reason == "26":
                    print "Traffic Purpose': Exfiltrate Cryptocurrency Wallet"
                elif Reason == "29":
                    print "Traffic Purpose': Exfiltrate Files"
                elif Reason == "2a":
                    print "Traffic Purpose': Exfiltrate POS Data"
                elif Reason == "2c":
                    print "Traffic Purpose': Exfiltrate Screenshots"
                print "\n"
    except AttributeError as e:
        # ignore packets that aren't TCP/UDP or IPv4
        pass


cap.apply_on_packets(Exfil, timeout=100)
