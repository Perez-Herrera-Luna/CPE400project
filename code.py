import dpkt
import socket
import ipinfo
import os
from dotenv import load_dotenv

load_dotenv()

# loads my IPinfo access token from .env file
# if the load fails or the .env file is not found, the program will run without an access token
try:
    access_token = os.getenv("IPINFO_ACCESS_TOKEN")
    handler = ipinfo.getHandler(access_token)
    print("IPINFO_ACCESS_TOKEN found in .env file")
except:
    print("Error: IPINFO_ACCESS_TOKEN not found in .env file")
    print("Note that the IPinfo API can be used without an access token, but in a \"limited capacity\"")
    print("Running without IPINFO_ACCESS_TOKEN")
    handler = ipinfo.getHandler()


packetCounter = 0
ipCounter = 0;
sharedIPCounter = 0;

filename1 = 'capture1.pcap'
filename2 = 'capture2.pcap'
filename3 = 'capture3.pcap'

destinationIPs = set()
sharedIPs = set()
sharedIPsString = set()

# reads capture1.pcap and adds unique IP addresses to a set
for ts, pkt in dpkt.pcap.Reader(open(filename1,'rb')):

    packetCounter += 1
    eth = dpkt.ethernet.Ethernet(pkt) 
    if eth.type != dpkt.ethernet.ETH_TYPE_IP:
        continue

    ip = eth.data
    ipCounter += 1


    # add unqiue IP addresses to a set
    destinationIPs.add(ip.dst)

# reads capture2.pcap and adds unique IP addresses to a set
for ts, pkt in dpkt.pcap.Reader(open(filename2,'rb')):

    packetCounter += 1
    eth = dpkt.ethernet.Ethernet(pkt) 
    if eth.type != dpkt.ethernet.ETH_TYPE_IP:
        continue

    ip = eth.data
    ipCounter += 1

    # add unqiue IP addresses to a set
    destinationIPs.add(ip.dst)

    # check if IP address is in the set
    if ip.dst in destinationIPs:
        sharedIPs.add(ip.dst)
        sharedIPCounter += 1

# reads capture3.pcap and adds unique IP addresses to a set
for ts, pkt in dpkt.pcap.Reader(open(filename3,'rb')):

    packetCounter += 1
    eth = dpkt.ethernet.Ethernet(pkt) 
    if eth.type != dpkt.ethernet.ETH_TYPE_IP:
        continue

    ip = eth.data
    ipCounter += 1

    # add unqiue IP addresses to a set
    destinationIPs.add(ip.dst)

    # check if IP address is in the set
    if ip.dst in destinationIPs:
        sharedIPs.add(ip.dst)
        sharedIPCounter += 1

print("\nTotal number of packets in the pcap files:", packetCounter)
print("Total number of IP packets:", ipCounter)
print("Total number of unique destination IP addresses:", len(destinationIPs))
print("Total number of shared IP addresses:", len(sharedIPs))
print("")

# convert IP address to string
for ip in sharedIPs:
    sharedIPsString.add(socket.inet_ntoa(ip))

# print IP address details
# uses IPinfo API to get details about IP address including hostname, city, and organization
for ip in sharedIPsString:
    print(ip)
    details = handler.getDetails(ip)

    try:
        print("Hostname: ", details.hostname)
    except:
        print("Hostname: ", "N/A")
    
    try:
        print("City: ", details.city)
    except:
        print("City: ", "N/A")

    try:
        print("Organization: ", details.org)
    except:
        print("Organization: ", "N/A")
    
    print("")