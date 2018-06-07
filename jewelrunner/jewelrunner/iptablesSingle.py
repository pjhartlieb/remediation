#!/usr/bin/python
#iptablesSingle.py

############################################################
#                                                          #
#                                                          #
#     [*] Ingesting logs and examining traffic between 2   #
#         hosts using ipTables                             #
#                                                          #
#     [-] Tested with:                                     #
#            RHEL Server 6.9                               #
#            iptables-1.4.7-16.el6.x86_64                  #
#                                                          #
#     [*] 2018.04.18                                       #
#          V0002                                           #
#          Black Lantern Security (BLS)                    #
#          @pjhartlieb                                     #
#                                                          #
#                                                          #
############################################################

# [*] REF

from colorama import init, Fore, Back, Style


def packetBucket(streams, targetHost, filterHost):
    """
    Sort unique connections by protocol for a host pair

    Args
    ----------
    streams (list): select metadata for each stream/conversation
    targetHost: The target IP being analyzed
    filterHost: The host the target is communicating with

    Return
    -------
    seeds (list): unique streams per protocol
    """
    seeds = []
    #TCP/UDP
    for stream in streams:
        # Go through each stream from the log file and extract entries for the target/filter IPs.
        if stream[0] == "TCP":
        # Simplified since every seed is for SYN packets only. The originators of the conversation is known
            if stream[1] == targetHost and stream[3] == filterHost:
                srcIP = stream[1]
                srcPort = stream[2]
                destinationIP = stream[3]
                destinationPort = stream[4]
                protocol = stream[0]
                interface = stream[5]
                iot = stream[6]
                seed = (srcIP, srcPort, destinationIP , destinationPort , protocol, interface)
                seeds.append(seed)
            elif stream[1] == filterHost and stream[3] == targetHost:
                srcIP = stream[1]
                srcPort = stream [2]
                destinationIP = stream[3]
                destinationPort = stream[4]
                protocol = stream[0]
                interface = stream[5]
                iot = stream[6]
                seed = (srcIP, srcPort, destinationIP , destinationPort , protocol, interface)
                seeds.append(seed)
        elif stream[0] == "UDP":
        # The SRC IP in the log entry is assumed to be the originator of the conversation. No assumptions made.
        # Its up to the operator to create more generalized rules
            if stream[1] == targetHost and stream[3] == filterHost:
                srcIP = stream[1]
                srcPort = stream[2]
                destinationIP = stream[3]
                destinationPort = stream[4]
                protocol = stream[0]
                interface = stream[5]
                iot = stream[6]
                seed = (srcIP, srcPort, destinationIP, destinationPort, protocol, interface)
                seeds.append(seed)
            elif stream[1] == filterHost and stream[3] == targetHost:
                srcIP = stream[1]
                srcPort = stream[2]
                destinationIP = stream[3]
                destinationPort = stream[4]
                protocol = stream[0]
                interface = stream[5]
                iot = stream[6]
                seed = (srcIP, srcPort, destinationIP, destinationPort, protocol, interface)
                seeds.append(seed)

    seeds = sorted(set(seeds))
    seeds = sorted(seeds, key=getKeyA)

    print(Fore.BLUE + '[' + Fore.WHITE + '-' + Fore.BLUE + ']' + Fore.GREEN + ' Mined ' +
        str(len(seeds)) + ' unique connections between %s and %s requiring iptables rules')% (targetHost,
                                                                                           filterHost)
    print ""
    for seed in seeds:
        print seed
    return seeds

def createRules(target, threads, outputFile):
    """
    Create rules statements based on unique conversations per protocol

    Args
    ----------
    target (string): the target host for which rules are being created
    threads (list): unique streams/conversations that need host-based rules

    Return
    -------
    n/a
    """
    rulesFile = open(outputFile, 'a')
    rulesCounter = 0

    for entry in threads:
        #all seed arrays are length 6
        #all seeds have already been sorted to include target IP and seed IP
        #tcp
        if entry[-2] == 'TCP' and entry[0] == target: #target initiates outbound connection
            rulesFile.write("# [-] " + "PORT " + str(entry[2]) + "\n")
            rulesFile.write("sudo iptables -A OUTPUT -o %s -p tcp --sport %s -d %s --dport %s -m conntrack --ctstate NEW,"
                            "ESTABLISHED -j ACCEPT\n" % (entry[4], entry[1], entry[2], entry[3]))
            rulesFile.write("sudo iptables -A INPUT -i %s -p tcp -s %s --sport %s --dport %s -m conntrack --ctstate ESTABLISHED -j ACCEPT\n"
                            % (entry[4], entry[2], entry[3], entry[1]))
            rulesFile.write("\n")
            rulesCounter = rulesCounter + 2

        elif entry[-2] == 'TCP' and entry[1] == target: #target receives inbound connection
            rulesFile.write("# [-] " + "PORT " + str(entry[2]) + "\n")
            rulesFile.write("sudo iptables -A INPUT -i %s -p tcp -s %s --dport %s -m conntrack --ctstate NEW,"
                            "ESTABLISHED -j ACCEPT\n" % (entry[4], entry[0], entry[2]))
            rulesFile.write("sudo iptables -A OUTPUT -i %s -p tcp --sport %s -d %s -m conntrack --ctstate ESTABLISHED -j ACCEPT\n"
                            % (entry[4], entry[2], entry[0]))
            rulesFile.write("\n")
            rulesCounter = rulesCounter + 2

        #udp
        if entry[-2] == 'UDP' and entry[0] == target: #Account for both to initiate connection if ports are equal
            rulesFile.write("# [-] " + "PORT " + str(entry[3]) + "\n")
            rulesFile.write("sudo iptables -A OUTPUT -o %s -p udp -m udp --sport %s -d %s --dport %s -j ACCEPT\n"
                            % (entry[5], entry[1], entry[2], entry[3]))
            rulesFile.write("sudo iptables -A INPUT -i %s -p udp -m udp -s %s --sport %s --dport %s -j ACCEPT\n"
                            % (entry[5], entry[2], entry[3], entry[1]))
            rulesFile.write("\n")
            rulesCounter = rulesCounter + 2
        elif entry[-2] == 'UDP' and entry[2] == target:
            rulesFile.write("# [-] " + "PORT " + str(entry[3]) + "\n")
            rulesFile.write("sudo iptables -A INPUT -i %s -p udp -m udp -s %s --sport %s --dport %s -j ACCEPT\n"
                            % (entry[5], entry[0],entry[1], entry[3]))
            rulesFile.write("sudo iptables -A OUTPUT -i %s -p udp -m udp --sport %s -d %s --dport %s -j ACCEPT\n"
                            % (entry[5], entry[3], entry[0], entry[1]))
            rulesFile.write("\n")
            rulesCounter = rulesCounter + 2


    rulesFile.close()

    print(Fore.BLUE + '[' + Fore.WHITE + '-' + Fore.BLUE + ']' + Fore.GREEN + ' Created ' +
                                           str(rulesCounter) + ' icmp, tcp, and udp rule(s) for ' + target)
    print ""


def getKeyA(item):
    """
    Define key so connections can be sorted by port

    Args
    ----------
    item(string):

    Return
    -------
    item(string):
    """
    return item[2]


def base(streams, targetHost, filterHost, outputFile):
    """
    Parse log data

    Args
    ----------
    streams (list): conversation data for all protocols and all hosts
    targetHost: The target IP being analyzed
    filterHost: The host the target is communicating with

    Return
    -------
    n/arm ipS
    """
    seeds = packetBucket(streams, targetHost, filterHost)
    createRules(targetHost, seeds, outputFile)