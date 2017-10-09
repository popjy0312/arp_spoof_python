from scapy.all import *

def cb(pkt):
    if "OTA" in str(pkt):
        print "##################################################"
        print "OTA!!!"
        print str(pkt)
        print "##################################################"
sniff(prn=cb)
