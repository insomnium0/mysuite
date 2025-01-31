#!/usr/bin/env python

# imports all the functions inside the scapy module, under the name scapy
import scapy.all as scapy

# imports the module to parse arguments
import argparse as arg

import re 

# function that initializes the "-t" argument, for the user to input a range of ip's
def ip_arg():
    parse = arg.ArgumentParser()
    parse.add_argument('-t','--target', dest='target', help ="input the ip address range you would like to scan")
    opts = parse.parse_args()
    regex = re.fullmatch(r"\d+\.\d+\.\d+\.\d+/\d+", opts.target)
    if regex:
        return opts
    else:
        print("input ip address range please. example: 10.0.0.1/24")
        exit()


# designates the iparg function to the "opts" variable, so that options.ipaddr can work, which is called for the scan.
opts = ip_arg()

# function to scan the network, 
def scan(ip):
    # creates the arp req variable, which is assigned to the scapy.arp object, which, you guessed it, sends an arp request.
    arp_req = scapy.ARP(pdst=ip)
    # creates an ethernet object, and stores the instance of the broadcast inside the "broadcast" variable. also makes sure the arp packet is sent to the broadcast MAC address, instead of only one device. the MAC address is a virtual MAC address, so it doesnt "exist", but anything sent to it will still be sent to all devices on the network.
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    # combines the output from broadcast and arp req into one packet, which can be called to later.
    arp_broadcast = broadcast/arp_req
    # the scapy.srp object sends the packet, and sends it as the MAC/broadcast combo packet above, so it asks every device on your network, "Hey! who has 10.0.0.2? who has 10.0.0.3? who has..." etc.
    answerlist = scapy.srp(arp_broadcast, timeout=1, verbose=False)[0]
   
    # creates an empty list for future use
    clients = []
    # for loop that prints out the ip/mac pair of every device on the given network, and puts every devices ip/mac into a dictionary, which is sort of just a bigger list. then it appends that dictionary to the empty clients list from above.
    for element in answerlist:
        client_dict = {"ip":element[1].psrc, "mac": element[1].hwsrc}
        clients.append(client_dict)
    return(clients)

# creates a function that returns the results. the (results) parameter is a placeholder, which gets replaced with the "scanres" variable at the end of this code, which returns all of the dictionaries that were being held by the "clients" list.
def print_result(results):
    # prints a nice header, for a cleaner look.
    print("\tIP\t\t|\tMAC Address\n____________________________________________________")
    # for every element (device) in results (clients), print the values held under the "ip" key, and the "mac" key, out of every dictionary that "clients" contains.
    for device in results:
        print(device["ip"]+"\t\t\t"+ device["mac"])
        

# puts the results of the ipaddr scan into the scanres variable. the "options.ipaddr" part specifically reads the input from the user, which should be a range of ip's
scanres = scan(opts.target)

# calls the print_result function, which prints the output of scanres, which in itself prints the output of the "scan" function.
print_result(scanres)