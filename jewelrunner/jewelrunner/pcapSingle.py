#!/usr/bin/python
#pcapSingle.py

############################################################
#                                                          #
#                                                          #
#    [*] Analyze traffic between the target and another    #
#        host                                              #
#                                                          #
#    [*] 2018.03.05                                        #
#          V0002                                           #
#          Black Lantern Security (BLS)                    #
#          @pjhartlieb                                     #
#                                                          #
#                                                          #
############################################################

import csv
from colorama import Fore


def parse_tcp_simple(tcpCollection, targetHost, filterHost):
    """
    Parse tcp packets. Analyze conversations between the target and a specific host

    Args
    ----------
    tcpCollection: Collection of TCP packets
    targetHost: The target IP being analyzed
    filterHost: The host the target is communicating with

    Return
    -------
    N/A
    """
    tcpPackets = tcpCollection
    if tcpPackets:
        L = len(tcpPackets)

        print ""
        print (Fore.BLUE + '[' + Fore.WHITE + '-' + Fore.BLUE + '] ' + Fore.GREEN +
               'Analyzing TCP packet data')
        print ""
        print Fore.BLUE + '\t[' + Fore.WHITE + '-' + Fore.BLUE + '] ' + Fore.GREEN + str(L) + " total TCP packets collected"

        destPorts_1 = []
        destPorts_2 = []
        ruleSeeds = []

        # Analyze conversations where the target was the destination host, SYN flag is set, and ACK flag is not set
        print (Fore.BLUE + '\t[' + Fore.WHITE + '-' + Fore.BLUE + '] ' + Fore.GREEN +
               'Mining TCP packets exchanged between %s (source) and %s (destination')% (filterHost, targetHost)
        print""
        for pair in tcpPackets:
            if (pair[2] == targetHost and pair[0] == filterHost and pair[4] and not pair[5]):
                seed = ("tcp", pair[0], pair[1], pair[2], pair[3])
                ruleSeeds.append(seed)
                dstPort = (pair[3])         #Capture the target port accessed
                destPorts_2.append(dstPort)

        dstPorts = sorted(set(destPorts_2)) #Create unique set for all target ports accessed
        print (Fore.BLUE + '\t\t[' + Fore.WHITE + '-' + Fore.BLUE + '] ' + Fore.GREEN + " %s as the destination host ") % targetHost
        print (Fore.BLUE + '\t\t[' + Fore.WHITE + '-' + Fore.BLUE + '] ' + Fore.GREEN + " %s as the source host ") % filterHost
        print ("\t\t - " + str(len(dstPorts)) + " unique TCP ports were accessed ON %s") % targetHost
        print""

        for port in dstPorts:               #Count packets for each port accessed on the targetHost
            counter = 0                     #Initialize list to capture conversations
            for candidate in ruleSeeds:
                if port == candidate[4]:
                    counter = counter + 1
            print ""
            print (Fore.GREEN + "\t\tdestination port: \t" + Fore.BLUE + port)
            print ""
            print (Fore.GREEN + "\t\tFiltered Host IP\t\tcount\t\t\ttype")
            print ("\t\t%s\t\t\t%s\t\t\tsyn packets" % (filterHost,counter))
            print ""

        # Parse data where the target was the source host, SYN flag is set and ACK flag is not set
        print (Fore.BLUE + '\t[' + Fore.WHITE + '-' + Fore.BLUE + '] ' + Fore.GREEN +
               'Mining TCP packets ecahnged between %s (source) and %s (destination')% (targetHost, filterHost)
        print""
        for pair in tcpPackets:
            if (pair[0] == targetHost and pair[2] == filterHost and pair[4] and not pair[5]):
                seed = ("tcp", pair[0], pair[1], pair[2], pair[3])
                ruleSeeds.append(seed)
                dstPort = (pair[3])                     #Capture the target port accessed
                destPorts_1.append(dstPort)

        dstPorts = sorted(set(destPorts_1))            #Create unique set for all target ports accessed
        print (Fore.BLUE + '\t\t[' + Fore.WHITE + '-' + Fore.BLUE + '] ' + Fore.GREEN + " %s as the source host ") % targetHost
        print (Fore.BLUE + '\t\t[' + Fore.WHITE + '-' + Fore.BLUE + '] ' + Fore.GREEN + " %s as the destination host ") % filterHost
        print ("\t\t - " + str(len(dstPorts)) + " unique TCP ports were accessed ON %s") % filterHost
        print""

        for port in dstPorts:       #Count packets for each IP that accessed ports on the target  IP
            counter = 0          #Initialize list to capture unique IPs accessing ports on the target host
            for candidate in ruleSeeds:
                if port == candidate[4]:
                    counter = counter + 1
            print ""
            print (Fore.GREEN + "\t\tdestination port: \t" + Fore.BLUE + port)
            print ""
            print (Fore.GREEN + "\t\tFiltered Host IP\t\tcount\t\t\ttype")
            print ("\t\t%s\t\t\t%s\t\t\tsyn packets" % (filterHost,counter))

        if ruleSeeds:
            with open( "/root/Desktop/tcp.csv", "wb") as csv_file:
                writer = csv.writer(csv_file, delimiter=',')
                print ""
                print (Fore.BLUE + '[' + Fore.WHITE + '-' + Fore.BLUE + '] ' + Fore.GREEN +
                       'Writing seeds for target IP TCP ruleset to CSV')
                print ""
                for seed in ruleSeeds:
                    writer.writerow(seed)
    else:
        print ""
        print (Fore.BLUE + '[' + Fore.WHITE + '-' + Fore.BLUE + '] ' + Fore.GREEN + 'Analyzing TCP packet data')
        print ""
        print Fore.BLUE + '\t[' + Fore.WHITE + '-' + Fore.BLUE + '] ' + Fore.GREEN + " 0 TCP packets collected"
        print ""


def parse_udp_simple(udpCollection, targetHost, filterHost):
    """
    Parse udp packets. Analyze conversations between the target and a specific host

    Args
    ----------
    udpCollection (list): collection of UDP packets
    targetHost (string): The target IP being analyzed
    filterHost (string): The host the target is communicating with

    Return
    -------
    N/A
    """
    udpPackets = udpCollection
    if udpPackets:
        L = len(udpPackets) #count total number of udp packets captured
        print ""
        print(Fore.BLUE + '[' + Fore.WHITE + '-' + Fore.BLUE + '] ' + Fore.GREEN +
              'Analyzing UDP packets')
        print ""
        print Fore.BLUE + '\t[' + Fore.WHITE + '-' + Fore.BLUE + '] ' + Fore.GREEN + str(L) + " total UDP packets collected"

        dstPorts_1 = []
        dstPorts_2 = []
        ruleSeeds = []

        # Parse data where the target IP was the destination host
        print (Fore.BLUE + '\t[' + Fore.WHITE + '-' + Fore.BLUE + '] ' + Fore.GREEN +
               'Mining TCP packets ecahnged between %s (source) and %s (destination')% (filterHost, targetHost)
        print""
        for pair in udpPackets:                             #Parse original list of UDP packets
            if pair[2] == targetHost and pair[0] == filterHost and int(pair[3]) <= 5000:
                seed = ("udp", pair[0], pair[1], pair[2], pair[3])
                ruleSeeds.append(seed)
                dstPort = (pair[3])                         #Capture the port accessed on the target IP
                dstPorts_2.append(dstPort)                  #Append to list of ports

        dstPorts = sorted(set(dstPorts_2))          #Create unique set for all target ports accessed
        print (Fore.BLUE + '\t\t[' + Fore.WHITE + '-' + Fore.BLUE + '] ' + Fore.GREEN +
               "%s as the destination host ") % targetHost
        print ("\t\t - " + str(len(dstPorts)) + " unique UDP ports were accessed ON %s") % targetHost
        print ""

        for port in dstPorts:       #Count how many packets each IP sent to each target port
            counter = 0                  #Initialize list to capture unique IPs accessing target port being considered
            for candidate in ruleSeeds:
                if port == candidate[4]:    #If the pair considered has the target port then operate on it
                    counter = counter +1

            print ""
            print (Fore.GREEN + "\t\tdestination port: \t" + Fore.BLUE + port)
            print ""
            print (Fore.GREEN + "\t\tFiltered Host IP\t\tcount")
            print ("\t\t%s\t\t\t%s" % (filterHost,counter))
            print ""

        # Parse data where the target IP was the source host
        print (Fore.BLUE + '\t[' + Fore.WHITE + '-' + Fore.BLUE + '] ' + Fore.GREEN +
               'Mining TCP packets ecahnged between %s (source) and %s (destination')% (targetHost, filterHost)
        print""
        for pair in udpPackets:  # Parse original list of UDP packets
            if pair[0] == targetHost and pair[2] == filterHost and int(pair[3]) <= 5000:
                seed = ("udp", pair[0], pair[1], pair[2], pair[3])
                ruleSeeds.append(seed)
                dstPort = (pair[3])  # Capture the port accessed on the target IP
                dstPorts_2.append(dstPort)  # Append to list of ports

        dstPorts = sorted(set(dstPorts_2))  # Create unique set for all target ports accessed
        print(Fore.BLUE + '\t\t[' + Fore.WHITE + '-' + Fore.BLUE + '] ' + Fore.GREEN +
              "%s as the source host ") % targetHost
        print("\t\t - " + str(len(dstPorts)) + " unique UDP ports were accessed ON %s") % filterHost
        print
        ""

        for port in dstPorts:  # Count how many packets each IP sent to each target port
            counter = 0  # Initialize list to capture unique IPs accessing target port being considered
            for candidate in ruleSeeds:
                if port == candidate[4]:  # If the pair considered has the target port then operate on it
                    counter = counter + 1

            print
            ""
            print(Fore.GREEN + "\t\tdestination port: \t" + Fore.BLUE + port)
            print
            ""
            print(Fore.GREEN + "\t\tFiltered Host IP\t\tcount")
            print("\t\t%s\t\t\t%s" % (filterHost, counter))
            print
            ""

        if ruleSeeds:
            with open("/root/Desktop/udp.csv", "wb") as csv_file:
                writer = csv.writer(csv_file, delimiter=',')
                print ""
                print (Fore.BLUE + '[' + Fore.WHITE + '-' + Fore.BLUE + '] ' + Fore.GREEN +
                       'Writing seeds for target IP UDP ruleset to CSV')
                print ""
                for seed in ruleSeeds:
                    writer.writerow(seed)
    else:
        print ""
        print (Fore.BLUE + '[' + Fore.WHITE + '-' + Fore.BLUE + '] ' + Fore.GREEN + 'Analyzing UD packet data')
        print ""
        print Fore.BLUE + '\t[' + Fore.WHITE + '-' + Fore.BLUE + '] ' + Fore.GREEN + " 0 UDP packets collected"
        print ""


def parse_icmp_simple(icmpCollection, targetHost, filterHost):
    """
    Parse icmp packets. Analyze conversations between the target and a specific host

    Args
    ----------
    icmpCollection (list): collection of ICMP packets
    targetHost (string): The target IP being analyzed
    filterHost (string): The host the target is communicating with

    Return
    -------
    N/A
    """
    icmpPackets = icmpCollection

    if icmpPackets:
        L = len(icmpPackets) #count total number of tcp packets captured
        print ""
        print (Fore.BLUE + '[' + Fore.WHITE + '-' + Fore.BLUE + '] ' + Fore.GREEN + 'Analyzing ICMP packet data')
        print ""
        print Fore.BLUE + '\t[' + Fore.WHITE + '-' + Fore.BLUE + '] ' + Fore.GREEN + str(L) + " total ICMP packets collected"
        print ""

        # Find unique hosts issuing ICMP ping requests
        targetSeeds = []
        filterSeeds = []

        for packet in icmpPackets:
            icmp = packet.data
            srcIP = pcapProcess.inet_to_str(packet.src)
            dstIP = pcapProcess.inet_to_str(packet.dst)

            if srcIP == targetHost and dstIP == filterHost and icmp.type == 8:
                targetSeed = ("icmp", srcIP, dstIP)
                targetSeeds.append(targetSeed)
            elif dstIP == targetHost and srcIP == filterHost and icmp.type == 8:
                filterSeed = ("icmp", srcIP, dstIP)
                filterSeeds.append(filterSeed)

        targetCount = len(targetSeeds)
        filterCount = len(filterSeeds)
        merged = targetSeeds + filterSeeds
        print Fore.BLUE + '\t[' + Fore.WHITE + '-' + Fore.BLUE + '] ' + Fore.GREEN + str(L) + " ICMP packet counts"
        print ""
        print (Fore.BLUE + '\t\t[' + Fore.WHITE + '-' + Fore.BLUE + '] ' + Fore.GREEN +
               "%s sent %s ICMP echo requests to %s ") % (targetHost, targetCount, filterHost)
        print ""
        print (Fore.BLUE + '\t\t[' + Fore.WHITE + '-' + Fore.BLUE + '] ' + Fore.GREEN +
               "%s sent %s ICMP echo requests to %s ") % (filterHost, filterCount, targetHost)
        print ""

        if merged:
            with open("/root/Desktop/icmp.csv", "wb") as csv_file:
                writer = csv.writer(csv_file, delimiter=',')
                print ""
                print (Fore.BLUE + '[' + Fore.WHITE + '-' + Fore.BLUE + '] ' + Fore.GREEN +
                       'Writing seeds for target/filter IPs ICMP ruleset to CSV')
                print ""
                merged = sorted(set(merged))
                for seed in merged:
                    writer.writerow(seed)

    else:
        print ""
        print (Fore.BLUE + '[' + Fore.WHITE + '-' + Fore.BLUE + '] ' + Fore.GREEN + 'Analyzing ICMP packets')
        print ""
        print Fore.BLUE + '\t[' + Fore.WHITE + '-' + Fore.BLUE + '] ' + Fore.GREEN + " 0 ICMP packets collected"
        print ""


def parse_igmp_simple(igmpCollection, targetHost, filterHost):
    """
    Parse igmp packets. Writes igmp "seeds" to output file for analysis and rule creation.

    Args
    ----------
    igmpCollection (list): collection of IGMP packets
    targetHost (string): The target IP being analyzed
    filterHost (string): The host the target is communicating with

    Return
    -------
    N/A
    """
    igmpPackets = igmpCollection

    if igmpCollection:
        L = len(igmpPackets) #count total number of tcp packets captured
        print ""
        print (Fore.BLUE + '[' + Fore.WHITE + '-' + Fore.BLUE + '] ' + Fore.GREEN + 'Analyzing IGMP packet data')
        print ""
        print (Fore.BLUE + '\t[' + Fore.WHITE + '-' + Fore.BLUE + '] ' + Fore.GREEN + str(L) + " total IGMP packets collected")
        print ""

        # Find unique hosts issuing IGMP membership reports
        targetSeeds = []
        filterSeeds = []

        for packet in igmpPackets:
            igmp = packet.data
            srcIP = pcapProcess.inet_to_str(packet.src)
            dstIP = pcapProcess.inet_to_str(packet.dst)

            if dstIP == targetHost and srcIP == filterHost and igmp.type == 34:
                filterseed = ("igmp", srcIP, dstIP)
                filterSeeds.append(filterseed)
            elif srcIP == targetHost and dstIP == filterHost and igmp.type == 34:
                targetseed = ("igmp", srcIP, dstIP)
                targetSeeds.append(targetseed)

        targetCount = len(targetSeeds)
        filterCount = len(filterSeeds)
        merged = targetSeeds + filterSeeds

        print Fore.BLUE + '\t[' + Fore.WHITE + '-' + Fore.BLUE + '] ' + Fore.GREEN + str(L) + " IGMP packet counts"
        print ""
        print(Fore.BLUE + '\t\t[' + Fore.WHITE + '-' + Fore.BLUE + '] ' + Fore.GREEN +
              "%s sent %s membership requests to %s ") % (targetHost, targetCount, filterHost)
        print ""
        print(Fore.BLUE + '\t\t[' + Fore.WHITE + '-' + Fore.BLUE + '] ' + Fore.GREEN +
              "%s sent %s membership requests to %s ") % (filterHost, filterCount, targetHost)
        print ""

        if merged:
            with open("/root/Desktop/igmp.csv", "wb") as csv_file:
                writer = csv.writer(csv_file, delimiter=',')
                print
                ""
                print(Fore.BLUE + '[' + Fore.WHITE + '-' + Fore.BLUE + '] ' + Fore.GREEN +
                      'Writing seeds for target/filter IPs IGMP ruleset to CSV')
                print
                ""
                merged = sorted(set(merged))
                for seed in merged:
                    writer.writerow(seed)
    else:
        print ""
        print(Fore.BLUE + '[' + Fore.WHITE + '-' + Fore.BLUE + '] ' + Fore.GREEN + 'Analyzing IGMP packets')
        print ""
        print Fore.BLUE + '\t[' + Fore.WHITE + '-' + Fore.BLUE + '] ' + Fore.GREEN + " 0 IGMP packets collected"
        print ""


def base(sortedContainer, targetHost, filterHost):
    """
    Parse conversation data

    Args
    ----------
    sortedContainer (list): conversation data for all protocols considered
    targetHost (string): The target IP being analyzed
    filterHost (string): The host the target is communicating with

    Return
    -------
    N/A
    """
    parse_tcp_simple(sortedContainer[0], targetHost, filterHost)
    parse_udp_simple(sortedContainer[1], targetHost, filterHost)
    parse_icmp_simple(sortedContainer[2], targetHost, filterHost)
    parse_igmp_simple(sortedContainer[3], targetHost, filterHost)