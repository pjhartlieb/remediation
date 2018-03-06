#!/usr/bin/python
#pcapProcess.py

############################################################
#                                                          #
#                                                          #
#    [*] Adopted from original scripts created by:         #
#        brifordwylie @ https://github.com/brifordwylie    #
#        RemiDesgrange @ https://github.com/RemiDesgrange  #
#        saylenty @ https://github.com/saylenty            #
#                                                          #
#    [*] Process and parse pcap file                       #
#                                                          #
#    [*] 2018.03.05                                        #
#          V0002                                           #
#          Black Lantern Security (BLS)                    #
#          @pjhartlieb                                     #
#                                                          #
#                                                          #
############################################################

import binascii
import csv
import socket
import dpkt
from colorama import init, Fore
from dpkt.compat import compat_ord
from jewelrunner import pcapSingle


def is_valid_pcap(pcapFile):
    """
    Verify pcap file header d4 c3 b2 a1

    Parameters
    ----------
    pcapFile : pcap file passed for processing

    Returns
    -------
    n/a
    """
    # d4 c3 b2 a1

    with open(pcapFile, "rb") as binary_file:
        # Read the whole file at once
        data = binary_file.read()

        # Seek position and read 4 bytes
        binary_file.seek(0)  # Go to beginning
        couple_bytes = binary_file.read(4)
        hex_data = binascii.hexlify(couple_bytes)
        if hex_data == 'd4c3b2a1':
            print(Fore.BLUE + '[' + Fore.WHITE + 'c' + Fore.BLUE + ']' + Fore.GREEN + ' PCAP header is clean')
            print ""
        else:
            print(Fore.BLUE + '[' + Fore.WHITE + 'e' + Fore.BLUE + ']' + Fore.GREEN + ' ERROR: pcap file is corrupt or '
                                                                         'incorrectly formatted')
            print""
            exit()


def readData(data):            # read in log file data
    """
    Open pcap file for operations

    Args
    ----------
    data (str): file passed at the command line

    Return
    -------
    data (list): line by line list for the pcap file entries
    """
    f=open(data, 'rb')
    pcap = dpkt.pcap.Reader(f)
    return pcap


def mac_addr(address):
    """
    Convert a MAC address to a readable/printable string

    Args
    ----------
    address (str): a MAC address in hex form (e.g. '\x01\x02\x03\x04\x05\x06')

    Return
    -------
    str: Printable/readable MAC address
    """
    return ':'.join('%02x' % compat_ord(b) for b in address)


def inet_to_str(inet):
    """
    Convert inet object to a string

    Args
    ----------
    inet (inet struct): inet network address

    Return
    -------
    str: Printable/readable IP address
    """
    # First try ipv4 and then ipv6
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)


def collect_tcp(tcp_ipPacket):
    """
    Parse tcp packets

    Args
    ----------
    tcp_ipPacket (eth.data):

    Return
    -------
    seed (list): source IP, source port, destination IP, destination port, and flags
    """
    ip = tcp_ipPacket
    tcpPayload =ip.data
    SRC_PORT = tcpPayload.sport
    DST_PORT = tcpPayload.dport
    syn_flag = ( tcpPayload.flags & dpkt.tcp.TH_SYN ) != 0
    ack_flag = ( tcpPayload.flags & dpkt.tcp.TH_ACK ) != 0
    seed=(inet_to_str(ip.src), str(SRC_PORT), inet_to_str(ip.dst), str(DST_PORT), syn_flag, ack_flag)
    return seed


def collect_udp(udp_ipPacket):
    """
    Parse udp packets

    Args
    ----------
    udp_ipPacket (eth.data):

    Return
    -------
    seed (list): source IP, source port, destination IP, and destination port
    """
    ip = udp_ipPacket
    udpPayload = ip.data

    if hasattr(udpPayload, 'sport'):
        SRC_PORT = udpPayload.sport
    else:
        SRC_PORT = 0

    if hasattr(udpPayload, 'dport'):
        DST_PORT = udpPayload.dport
    else:
        DST_PORT = 0

    seed=(inet_to_str(ip.src), str(SRC_PORT), inet_to_str(ip.dst), str(DST_PORT))
    return seed


def collect_arp(arp_ethPacket):
    """
    Parse arp packets

    Args
    ----------
    arp_ethPacket (eth.data):

    Return
    -------
    seed (list): source and destination mac addresses
    """
    arp = arp_ethPacket
    seed=(mac_addr(arp.sha), mac_addr(arp.tha))
    return seed


def collect_ip6(ip6_ethPacket):
    """
    Parse ipv6 packet

    Args
    ----------
    ip6_ethPacket (eth.data):

    Return
    -------
    seed (list): source and destination ipv6 addresses
    """
    ip6 = ip6_ethPacket
    dst_ip_addr_str = socket.inet_ntop(socket.AF_INET6, ip6.dst)
    src_ip_addr_str = socket.inet_ntop(socket.AF_INET6, ip6.src)
    seed=(src_ip_addr_str, dst_ip_addr_str)
    return seed


def collect_cdn(cdn_ethPacket):
    """
    Parse cdn packets

    Args
    ----------
    cdn_ethPacket (eth.data):

    Return
    -------
    cdn: cdn packet
    """
    cdn = cdn_ethPacket
    return cdn


def parse_igmp(igmpCollection, ip):
    """
    Parse igmp packets. Writes igmp "seeds" to output file for analysis and rule creation.

    Args
    ----------
    igmpCollection (list): collection of IGMP packets
    ip (string): the target IP being analyzed

    Return
    -------
    N/A
    """
    igmpPackets = igmpCollection
    target = ip
    L = len(igmpPackets) #count total number of tcp packets captured
    print ""
    print (Fore.BLUE + '[' + Fore.WHITE + '-' + Fore.BLUE + '] ' + Fore.GREEN + 'Mining IGMP packets')
    print ""
    print (Fore.BLUE + '\t[' + Fore.WHITE + '-' + Fore.BLUE + '] ' + Fore.GREEN + str(L) + " total IGMP packets collected")
    print ""

    # Find unique hosts issuing IGMP membership reports
    igmpTAMS = []
    igmpNetwork = []
    ruleSeeds = []
    for packet in igmpPackets:
        igmp = packet.data
        srcIP = inet_to_str(packet.src)
        dstIP = inet_to_str(packet.dst)

        if dstIP == target and igmp.type == 34:
            igmpNetwork.append(srcIP)
            igmpNetwork = sorted(set(igmpNetwork))
            seed = ("igmp", srcIP, dstIP)
            ruleSeeds.append(seed)
        elif srcIP == target and igmp.type == 34:
            igmpTAMS.append(dstIP)
            igmpTAMS = sorted(set(igmpTAMS))
            seed = ("igmp", srcIP, dstIP)
            ruleSeeds.append(seed)

    print ""
    print (Fore.BLUE + '\t\t[' + Fore.WHITE + '-' + Fore.BLUE + '] ' + Fore.GREEN +
           "%s as the source") % target
    print ("\t\t - " + str(len(igmpTAMS)) + " unique hosts received membership reports FROM %s") % target
    print ""
    print " \t\t source IPs:"

    for candidate in igmpTAMS:
        print (" \t\t\t" + candidate)
    print ""

    print (Fore.BLUE + '\t\t[' + Fore.WHITE + '-' + Fore.BLUE + '] ' + Fore.GREEN + \
          "Other Network hosts host ")
    print ("\t\t - " + str(len(igmpNetwork)) + " unique hosts sent membership reports TO %s") % target
    print ""
    print " \t\t source IPs:"

    for candidate in igmpNetwork:
        print ("\t\t\t" + candidate)

    print ""

    if ruleSeeds:
        with open("/root/Desktop/igmp.csv", "wb") as csv_file:
            writer = csv.writer(csv_file, delimiter=',')
            print ""
            print (Fore.BLUE + '[' + Fore.WHITE + '-' + Fore.BLUE + '] ' + Fore.GREEN + 'Writing seeds for target IP IGMP ruleset to CSV')
            print ""
            sortedruleSeeds = sorted(set(ruleSeeds))
            for seed in sortedruleSeeds:
                writer.writerow(seed)


def parse_icmp(icmpCollection, ip):
    """
    Parse icmp packets. Writes icmp "seeds" to output file for analysis and rule creation.

    Args
    ----------
    igmpCollection (list): collection of ICMP packets
    ip (string): the target IP being analyzed

    Return
    -------
    N/A
    """
    icmpPackets = icmpCollection
    target = ip
    L = len(icmpPackets) #count total number of tcp packets captured
    print ""
    print (Fore.BLUE + '[' + Fore.WHITE + '-' + Fore.BLUE + '] ' + Fore.GREEN + 'Analyzing ICMP packets')
    print ""
    print Fore.BLUE + '\t[' + Fore.WHITE + '-' + Fore.BLUE + '] ' + Fore.GREEN + str(L) + " total ICMP packets collected"
    print ""

    # Find unique hosts issuing ICMP ping requests
    icmpTAMS = []
    icmpTargets = []
    ruleSeeds = []
    for packet in icmpPackets:
        icmp = packet.data
        srcIP = inet_to_str(packet.src)
        dstIP = inet_to_str(packet.dst)

        if dstIP == target and icmp.type == 8:
            icmpTAMS.append(srcIP)
            icmpTAMS = sorted(set(icmpTAMS))
            seed = ("icmp", srcIP, dstIP)
            ruleSeeds.append(seed)
        elif srcIP == target and icmp.type == 8:
            icmpTargets.append(dstIP)
            icmpTargets = sorted(set(icmpTargets))
            seed = ("icmp", srcIP, dstIP)
            ruleSeeds.append(seed)

    print ""
    print (Fore.BLUE + '\t\t[' + Fore.WHITE + '-' + Fore.BLUE + '] ' + Fore.GREEN +
           "%s as the destination host ") % target
    print ("\t\t - " + str(len(icmpTAMS)) + " unique hosts sent ICMP echo requests TO %s") % target
    print ""
    print " \t\t source IPs:"

    for candidate in icmpTAMS:
        print (" \t\t\t" + candidate)
    print ""

    print (Fore.BLUE + '\t\t[' + Fore.WHITE + '-' + Fore.BLUE + '] ' + Fore.GREEN +
           "%s as the source host") % target
    print ("\t\t - " + str(len(icmpTargets)) + " unique hosts received ICMP echo requests FROM %s") % target
    print ""
    print " \t\t destination IPs:"

    for candidate in icmpTargets:
        print ("\t\t\t" + candidate)

    print ""

    if ruleSeeds:
        with open("/root/Desktop/icmp.csv", "wb") as csv_file:
            writer = csv.writer(csv_file, delimiter=',')
            print ""
            print (Fore.BLUE + '[' + Fore.WHITE + '-' + Fore.BLUE + '] ' + Fore.GREEN +
                   'Writing seeds for target IP ICMP ruleset to CSV')
            print ""
            sortedruleSeeds = sorted(set(ruleSeeds))
            for seed in sortedruleSeeds:
                writer.writerow(seed)


def parse_udp(udpCollection, ip):
    """
    Parse udp packets. Writes udp "seeds" to output file for analysis and rule creation.

    Args
    ----------
    udpCollection (list): collection of UDP packets
    ip (string): the target IP being analyzed

    Return
    -------
    N/A
    """
    udpPackets = udpCollection
    target = ip
    L = len(udpPackets) #count total number of udp packets captured
    print ""
    print(Fore.BLUE + '[' + Fore.WHITE + '-' + Fore.BLUE + '] ' + Fore.GREEN +
          'Analyzing UDP packets')
    print ""
    print Fore.BLUE + '\t[' + Fore.WHITE + '-' + Fore.BLUE + '] ' + Fore.GREEN + str(L) + " total UDP packets collected"
    udpSorted = sorted(set(udpPackets)) #count the unique src:port ---> dst:port pairs
    LS = len(udpSorted)
    print Fore.BLUE + '\t[' + Fore.WHITE + '-' + Fore.BLUE + '] ' + Fore.GREEN + str(LS) + " unique src:port ---> dst:port pairs"
    print ""
    streamPairs_1 = []  #initialize list to capture all src/dst pairs where target was the source
    dstPorts_1 = []     #initialize list to capture all ports accessed by the target on remote hosts

    dstPorts_2 = []     #initialize list to capture the destination ports accessed by remote hosts on target
    streamPairs_2 = []  #initialize list to capture all pairs where target was the destination

    ruleSeeds = []  # Initialize list to capture seed for firewall rule

    # Parse data where the target IP was the destination host
    print (Fore.BLUE + '\t[' + Fore.WHITE + '-' + Fore.BLUE + '] ' + Fore.GREEN +
           'Mining UDP packets with target as the destination host')
    print""
    for pair in udpPackets:                             #Parse original list of UDP packets
        if pair[2] == target and int(pair[3]) <= 5000:
            seed = ("udp", pair[0], pair[1], pair[2], pair[3])
            ruleSeeds.append(seed)
            dstPair = (pair[0], pair[2], pair[3])       #Capture stream pair and remove src port
            dstPort = (pair[3])                         #Capture the port accessed on the target IP
            dstPorts_2.append(dstPort)                  #Append to list of ports
            streamPairs_2.append(dstPair)               #Append pair to list
    uniquedstPorts_2 = sorted(set(dstPorts_2))          #Create unique set for all target ports accessed
    uniquestreamPairs_2 = sorted(set(streamPairs_2))    #Create unique pairs accessing target ports
    print (Fore.BLUE + '\t\t[' + Fore.WHITE + '-' + Fore.BLUE + '] ' + Fore.GREEN +
           "%s as the destination host ") % target
    print ("\t\t - " + str(len(uniquedstPorts_2)) + " unique UDP ports were accessed ON %s") % target
    print ("\t\t - " + str(len(uniquestreamPairs_2)) + " unique IPs accessing UDP ports ON %s") % target
    print ""

    for port in uniquedstPorts_2:       #Count how many packets each IP sent to each target port
        sourceIPs = []                  #Initialize list to capture unique IPs accessing target port being considered
        for candidate in streamPairs_2:
            if port == candidate[2]:    #If the pair considered has the target port then operate on it
                sourceIPs.append(candidate[0]) #Capture the source IP accessing the port
        print (Fore.GREEN + "\t\tdestination port: \t" + Fore.BLUE + port)
        print ""
        print (Fore.GREEN + "\t\tsource IPs\t\t\tcount")
        uniquesourceIPs=sorted(set(sourceIPs)) #Create a unique list of source IPs
        for candidate in uniquesourceIPs:      #Count how many packets sent by the source IP to port on the target IP
            count=sourceIPs.count(candidate)
            print ("\t\t%s\t\t\t%s" % (candidate,count))
        print ""

    # Parse data where the target IP was the source host
    print (Fore.BLUE + '\t[' + Fore.WHITE + '-' + Fore.BLUE + '] ' + Fore.GREEN + 'Mining UDP packets with target as the source host')
    print""
    for pair in udpPackets:
        if (pair[0] == target and int(pair[3]) <= 5000):
            seed = ("udp", pair[0], pair[1], pair[2], pair[3])
            ruleSeeds.append(seed)
            srcPair = (pair[0], pair[2], pair[3])   #Capture stream pair and remove src port
            dstPort = (pair[3])                     #Capture the port accessed on the remote host by the target IP
            dstPorts_1.append(dstPort)              #Append to list of ports
            streamPairs_1.append(srcPair)           #Append pair to list
    dstPorts = sorted(set(dstPorts_1))              #Create unique set for all target ports accessed
    targetSorted = sorted(set(streamPairs_1))       #Create unique pairs accessing target ports
    print (Fore.BLUE + '\t\t[' + Fore.WHITE + '-' + Fore.BLUE + '] ' + Fore.GREEN + "%s as the source host ") % target
    print ("\t\t - " + str(len(dstPorts)) + " unique UDP ports were accessed BY %s") % target
    print ("\t\t - " + str(len(targetSorted)) + " unique IPs accessed BY %s") % target

    for port in dstPorts: #Count how many packets the target IP sent to each target port on the destination host
        destIPs = [] #Initialize list to capture unique IPs that the target host is accessing
        for candidate in streamPairs_1:
            if port == candidate[2]:
                destIPs.append(candidate[1])
        print ""
        print (Fore.GREEN + "\t\tdestination port: \t" + Fore.BLUE + port)
        print ""
        print (Fore.GREEN + "\t\tdestination IPs\t\t\tcount")
        uniquedestIPs=sorted(set(destIPs))
        for candidate in uniquedestIPs:
            count = destIPs.count(candidate)
            print ("\t\t%s\t\t\t%s" % (candidate, count))
        print ""

    if ruleSeeds:
        with open("/root/Desktop/udp.csv", "wb") as csv_file:
            writer = csv.writer(csv_file, delimiter=',')
            print ""
            print (Fore.BLUE + '[' + Fore.WHITE + '-' + Fore.BLUE + '] ' + Fore.GREEN +
                   'Writing seeds for target IP UDP ruleset to CSV')
            print ""
            for seed in ruleSeeds:
                writer.writerow(seed)


def parse_tcp(tcpCollection, ip):
    """
    Parse tcp packets. Writes tcp "seeds" to output file for analysis and rule creation.

    Args
    ----------
    tcpCollection (list): collection of TCP packets
    ip (string): the target IP being analyzed

    Return
    -------
    N/A
    """
    tcpPackets = tcpCollection
    target = ip
    L = len(tcpPackets) #Count total number of tcp packets captured
    print ""
    print (Fore.BLUE + '[' + Fore.WHITE + '-' + Fore.BLUE + '] ' + Fore.GREEN +
           'Analyzing TCP packets')
    print ""
    print Fore.BLUE + '\t[' + Fore.WHITE + '-' + Fore.BLUE + '] ' + Fore.GREEN + str(L) + " total TCP packets collected"

    tcpSorted = sorted(set(tcpPackets)) #Count the unique src:port ---> dst:port pairs
    LS = len(tcpSorted)
    print Fore.BLUE + '\t[' + Fore.WHITE + '-' + Fore.BLUE + '] ' + Fore.GREEN + str(LS) + " unique src:port ---> dst:port pairs"

    streamPairs_1 = []      #Initialize list to capture all src/dst pairs where target was the source
    destPorts_1 = []        #Initialize list to capture all ports accessed by target on remote hosts

    destPorts_2 = []        #Initialize list to capture the destination ports accessed by remote hosts on target
    streamPairs_2 = []      #Initialize list to capture all pairs where target was the destination

    ruleSeeds = []          #Initialize list to capture seed for firewall rule
    print ""
    # Parse data where the target was the destination host, SYN flag is set and ACK flag is not set
    print (Fore.BLUE + '\t[' + Fore.WHITE + '-' + Fore.BLUE + '] ' + Fore.GREEN +
           'Mining TCP packets with target as the destination host')
    print""
    for pair in tcpPackets:
        if (pair[2] == target and pair[4] and not pair[5]):
            seed = ("tcp", pair[0], pair[1], pair[2], pair[3])
            ruleSeeds.append(seed)
            dstPair = (pair[0], pair[2], pair[3])   #Capture pair and remove src port
            dstPort = (pair[3])                     #Capture the target port accessed
            destPorts_2.append(dstPort)
            streamPairs_2.append(dstPair)
    dstPorts = sorted(set(destPorts_2))            #Create unique set for all target ports accessed
    targetSorted = sorted(set(streamPairs_2))      #Create unique pairs accessing target ports
    print (Fore.BLUE + '\t\t[' + Fore.WHITE + '-' + Fore.BLUE + '] ' + Fore.GREEN + " %s as the destination host ") % target
    print ("\t\t - " + str(len(dstPorts)) + " unique TCP ports were accessed ON %s") % target
    print ("\t\t - " + str(len(targetSorted)) + " unique IPs accessed TCP ports ON %s") % target
    print""
    for port in dstPorts:       #Count packets for each IP that accessed ports on the target  IP
        sourceIPs = []          #Initialize list to capture unique IPs accessing ports on the target host
        for candidate in streamPairs_2:
            if port == candidate[2]:
                sourceIPs.append(candidate[0])
        print ""
        print ("\t\t destination port: \t" + Fore.BLUE + port)
        print "\t\t source IPs:"
        uniquesourceIPs = sorted(set(sourceIPs)) # Create a unique list of source IPs
        for candidate in uniquesourceIPs:        #Count how many packets sent by the source IP to port on the target IP
            count=sourceIPs.count(candidate)
            print ("\t\t%s\t\t\t%s\t\t\tsyn packets" % (candidate,count))
        print ""

    # Parse data where target IP was the source host
    print (Fore.BLUE + '\t[' + Fore.WHITE + '-' + Fore.BLUE + '] ' + Fore.GREEN +
           'Mining TCP packets with target as the source host')
    print""
    for pair in tcpSorted:
        if (pair[0] == target and pair[4] and not pair[5]):
            seed = ("tcp", pair[0], pair[1], pair[2], pair[3])
            ruleSeeds.append(seed)
            srcPair = (pair[0], pair[2], pair[3])   #Capture pair and remove ephemeral src port)
            dstPort = (pair[3])                     #Capture the port accessed by target
            destPorts_1.append(dstPort)
            streamPairs_1.append(srcPair)
    destPorts_1 = sorted(set(destPorts_1))
    targetSorted = sorted(set(streamPairs_1))
    print (Fore.BLUE + '\t\t[' + Fore.WHITE + '-' + Fore.BLUE + '] ' + Fore.GREEN + "%s as the source host ") % target
    print ("\t\t - " + str(len(destPorts_1)) + " unique TCP ports were accessed BY %s") % target
    print ("\t\t - " + str(len(targetSorted)) + " unique IPs accessed BY %s") % target

    for port in destPorts_1:    #List IPs that accessed each target port
        destIPs = []            #Initialize list to capture unique IPS accessing target port being considered
        for candidate in streamPairs_1:
            if port == candidate[2]:
                destIPs.append(candidate[1])
        print ""
        print (Fore.GREEN + "\t\tdestination port: \t" + Fore.BLUE + port)
        print ""
        print (Fore.GREEN + "\t\tdestination IP\t\t\tcount\t\t\ttype")
        uniquedestIPs = sorted(set(destIPs))    #Create a unique list of destination IPs
        for candidate in uniquedestIPs:         #Count how many packets sent by the target IP to port on the dest host
            count=destIPs.count(candidate)
            print ("\t\t%s\t\t\t%s\t\t\tsyn packets" % (candidate,count))
        print ""

    if ruleSeeds:
        with open( "/root/Desktop/tcp.csv", "wb") as csv_file:
            writer = csv.writer(csv_file, delimiter=',')
            print ""
            print (Fore.BLUE + '[' + Fore.WHITE + '-' + Fore.BLUE + '] ' + Fore.GREEN +
                   'Writing seeds for target IP TCP ruleset to CSV')
            print ""
            for seed in ruleSeeds:
                writer.writerow(seed)


def print_remainder(ipv6Pkts, cdnPkts, arpPkts):
    """
    Parse remaining packets. Prints statistics for ipv6, cdn , and arp packets.

    Args
    ----------
    ipv6Pkts (list): collection of ipv6 packets
    cdnPkts (list): collection of cdn packets
    arpPkts (list): collection of arp packets

    Return
    -------
    N/A
    """
    # Print IPV6 seeds
    V = len(ipv6Pkts)
    print (Fore.BLUE + '[' + Fore.WHITE + '-' + Fore.BLUE + '] ' + Fore.GREEN + str(V) +
           ' IPV6 packets collected')
    print ""

    # Print CDN seeds
    N = len(cdnPkts)
    print (Fore.BLUE + '[' + Fore.WHITE + '-' + Fore.BLUE + '] ' + Fore.GREEN + str(N) +
           ' CDN packets collected')
    print""

    # Print ARP seeds
    A = len(arpPkts)
    print (Fore.BLUE + '[' + Fore.WHITE + '-' + Fore.BLUE + '] ' + Fore.GREEN + str(A) +
           ' ARP packets collected')
    print ""
    print "END"
    print ""


def sort_packets(pcap):
    """
    Sort packets according to type. Packets are identified and then passed to the appropriate collection function. The
    collection function parses the packet and creates a seed. The seed is appended to the packet-specific list.

    Args
    ----------
    pcap (dpkt.pcap.Reader(f)): pcap file that has been read in and processed using dpkt, This is a dpkt.pcap.Reader(f) object.

    Return
    -------
    packetBox (list): a list of lists. each list contains a specific packet type
    """
    # Initialize arrays to capture traffic types
    tcpPkts = []
    udpPkts = []
    icmpPkts = []
    igmpPkts = []
    arpPkts = []
    ipv6Pkts = []
    cdnPkts = []
    unknownPkts = []
    counter=0
    tCounter=0
    packets = []
    init(autoreset=True)


    # For each packet in the pcap process the contents
    for timestamp, buf in pcap:
        tCounter=tCounter+1

        # Unpack the Ethernet frame (mac src/dst, ethertype)
        eth = dpkt.ethernet.Ethernet(buf)

    # Check whether IP packets: to consider only IP packets
        if isinstance(eth.data, dpkt.ip.IP):
            ip=eth.data

            if ip.p==dpkt.ip.IP_PROTO_TCP: # Check for TCP packets
                seed = collect_tcp(ip)
                tcpPkts.append(seed)

            elif ip.p==dpkt.ip.IP_PROTO_UDP: # Check for UDP packets
                seed = collect_udp(ip)
                udpPkts.append(seed)

            elif ip.p==dpkt.ip.IP_PROTO_ICMP: #Check for ICMP packets
                #pass the entire packet to parse_icmp()
                icmpPkts.append(ip)

            elif ip.p==dpkt.ip.IP_PROTO_IGMP: #Check for IGMP packets
                #seed = collect_igmp(ip)
                igmpPkts.append(ip)

        elif eth.type==dpkt.ethernet.ETH_TYPE_ARP:
            arp=eth.data
            seed = collect_arp(arp)
            arpPkts.append(seed)

        elif eth.type==dpkt.ethernet.ETH_TYPE_IP6:
            ipv6=eth.data
            seed = collect_ip6(ipv6)
            ipv6Pkts.append(seed)

        elif eth.type==389:
            cdn=eth.data
            seed = collect_cdn(cdn)
            cdnPkts.append(seed)

        else:
            #print('Non IP Packet type not supported %s\n' % eth.type)
            d=eth.type
            unknownPkts.append(d)
            counter=counter+1

    packetBox = [tcpPkts, udpPkts, icmpPkts, igmpPkts, ipv6Pkts, cdnPkts, arpPkts ]

    print Fore.BLUE + '[' + Fore.WHITE + '-' + Fore.BLUE + '] ' + Fore.GREEN + str(tCounter) + \
          " Total packets collected"
    print ""
    #Print unclassified
    print Fore.BLUE + '[' + Fore.WHITE + '-' + Fore.BLUE + '] ' +  Fore.GREEN + str(counter) + \
          " Unclassified packets"
    unknownPkts = sorted(set(unknownPkts))

    return packetBox


def sortPcap(inputFile, ip, inputFilter):
    """
    A pcap file will be processed in 1 of 2 ways. If there is both an ip for the target (ip) and an ip for a specific
    host (inputFilter) then the pcap will be parsed for conversations between these 2 hosts only. If there is only a
    target ip, then the pcap will be parsed for all conversations.

    Args
    ----------
    inputFile (dpkt.pcap.Reader(f)): pcap file that has been read in and processed using dpkt, This is a
    dpkt.pcap.Reader(f) object.
    ip (string): the target IP being analyzed
    inputFilter (sting): the specific host to filter conversations on

    Return
    -------
    N/A
    """
    is_valid_pcap(inputFile)
    pcap = readData(inputFile)

    print (Fore.BLUE + '[' + Fore.WHITE + '-' + Fore.BLUE + ']' + Fore.GREEN + ' Analyzing file %s') %(inputFile)
    print ""
    print(Fore.BLUE + '[' + Fore.WHITE + '-' + Fore.BLUE + ']' + Fore.GREEN + ' Target(host) IP: %s') % (ip)
    print""

    if inputFilter:
        print(Fore.BLUE + '[' + Fore.WHITE + '-' + Fore.BLUE + ']' + Fore.GREEN + ' Filtered(host) IP: %s') \
        % (inputFilter)
        print""
        sortedContainer = sort_packets(pcap)
        pcapSingle.base(sortedContainer, ip, inputFilter)
    else:
        sortedContainer = sort_packets(pcap)
        parse_tcp(sortedContainer[0], ip)
        parse_udp(sortedContainer[1], ip)
        parse_icmp(sortedContainer[2], ip)
        parse_igmp(sortedContainer[3], ip)
        print_remainder(sortedContainer[4],sortedContainer[5],sortedContainer[6])