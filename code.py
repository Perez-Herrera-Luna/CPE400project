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
fileCounterIndex = 0;

filenames = ["capture1.pcap", "capture2.pcap", "capture3.pcap", "capture4.pcap", "capture5.pcap", "capture6.pcap", "capture7.pcap", "capture8.pcap", "capture9.pcap", "capture10.pcap"]

destinationIPs = set()
sharedIPs = set()
sharedIPsString = set()

# read initial pcap file to from destination IP address set
for ts, pkt in dpkt.pcap.Reader(open(filenames[0],'rb')):
    packetCounter += 1
    # read IPv4 packets from non ethernet frames
    ip = dpkt.ip.IP(pkt)
    # verify that the packet is IPv4 and TCP (has a valid destination IP address)
    if ip.p != dpkt.ip.IP_PROTO_TCP:
        continue

    ipCounter += 1

    # check if IP address is in the set
    # add unqiue IP addresses to a set
    try:
        destinationIPs.add(ip.dst)
    except:
        pass

# read remaining pcap files. If the destination IP address is already in the set, add it to the shared IP address set
for filename in filenames[1:]:
    for ts, pkt in dpkt.pcap.Reader(open(filename,'rb')):
        packetCounter += 1
        # read IPv4 packets from non ethernet frames
        ip = dpkt.ip.IP(pkt)
        # verify that the packet is IPv4 and TCP (has a valid destination IP address)
        if ip.p != dpkt.ip.IP_PROTO_TCP:
            continue

        ipCounter += 1

        # check if IP address is in the set
        try:
            if ip.dst in destinationIPs:
                sharedIPs.add(ip.dst)
                sharedIPCounter += 1

            # add unique IP addresses to a set
            destinationIPs.add(ip.dst)
        except:
            pass

print("\nTotal number of packets in the pcap files:", packetCounter)
print("Total number of IP packets:", ipCounter)
print("Total number of unique destination IP addresses:", len(destinationIPs))
print("Total number of shared IP addresses:", len(sharedIPs))
print("")

# convert IP address to string
for ip in sharedIPs:
    sharedIPsString.add(socket.inet_ntoa(ip))

akamaiCounter = 0 # counts the number of Akamai IP addresses

# print IP address details
# uses IPinfo API to get details about IP address including hostname, city, and organization
for ip in sharedIPsString:
    details = handler.getDetails(ip)

    # skip Akamai IP addresses
    try:
        if "Akamai" in details.org:
            akamaiCounter += 1
            continue
    except:
        pass

    print(ip)

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

print("Skipped", akamaiCounter, "Akamai IP addresses")