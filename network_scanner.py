#!/usr/bin/env pyhton

import scapy.all as scapy
import optparse

def scan(ip):
    arp_req = scapy.ARP(pdst = ip)
    braodcast = scapy.Ether(dst = 'ff:ff:ff:ff:ff:ff')
    arp_broadcast_req = braodcast/arp_req
    answered_list = scapy.srp(arp_broadcast_req, timeout = 1,verbose=False)[0]
    client = []
    for element in answered_list:
        target_client = {'mac': str(element[1].hwsrc),'ip': str(element[1].psrc)}
        client.append(target_client)
    return client

def getArgs():
    Parser = optparse.OptionParser()
    Parser.add_option('-t','--target',dest='TARGET',help='PLEASE SPECIFY THE TARGET IP OR LIST ')
    (options,arguments)=Parser.parse_args()
    return options

def print_result(result_list):
    print('----------------------------------------------\nIP\t\t\tMAC ADDRESS\n----------------------------------------------')
    for list in result_list :
        print(list['ip'] + '\t\t' + list['mac'])

scan_result = scan(getArgs().TARGET)
print_result(scan_result)
