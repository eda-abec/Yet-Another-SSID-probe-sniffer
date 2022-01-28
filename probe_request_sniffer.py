#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# WiFi probe request sniffer (passive)

# (C) 2014 Adam Ziaja <adam@adamziaja.com> http://adamziaja.com
# 2022 edit by eda-abec

from scapy.all import *
from sys import argv
from datetime import datetime

def get_time():
    return datetime.strftime(datetime.now(),'[%m/%d %H:%M:%S]')

interface = argv[1]

try:
    # curl -s "https://code.wireshark.org/review/gitweb?p=wireshark.git;a=blob_plain;f=manuf;hb=HEAD" > manuf.txt
    manuf = open("manuf.txt").read()
except:
    manuf = ""
unique_probe = []

def Handler(pkt):
    if pkt.haslayer(Dot11): # 802.11
        if pkt.type == 0 and pkt.subtype == 4: # mgmt, probe request
            ssid_mac = str(pkt.info, "utf8") + "_" + pkt.addr2
            if ssid_mac not in unique_probe and len(pkt.info) > 0:
                unique_probe.append(ssid_mac)
                mac = ":".join(pkt.addr2.split(":")[:3]).upper()
                try:
                    vendor = ", " + "\n".join(line for line in manuf.splitlines() if line.startswith(mac)).split("# ")[1]
                except IndexError:
                    vendor = ""
                print("%s %s%s: %s" % (get_time(), pkt.addr2, vendor, str(pkt.info, "utf8")))
                #print pkt.show()
                #pkt.pdfdump(filename=ssid_mac + ".pdf") # sudo apt-get install -y python-pyx

try:
     # sudo rfkill unblock wifi && sudo airmon-ng start wlan0
     sniff(iface=interface, count=0, prn=Handler, store=0)
except KeyboardInterrupt:
    pass
