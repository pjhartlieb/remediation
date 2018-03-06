#!/usr/bin/python
#ipfilterSingle.py

############################################################
#                                                          #
#                                                          #
#     [*] Ingesting logs and examining traffic between 2   #
#         hosts                                            #
#                                                          #
#     [-] Tested with:                                     #
#            /var/log/ipfmon.log                           #
#            SunOS ATL050 5.10 Generic_150401 - 52         #
#            IP Filter: v4.1.9 (592)                       #
#                                                          #
#     [*] 2018.03.05                                       #
#          V0002                                           #
#          Black Lantern Security (BLS)                    #
#          @pjhartlieb                                     #
#                                                          #
#                                                          #
############################################################

from colorama import init, Fore, Back, Style


def packetBucket(streams, targetHost, filterHost):
    """
    Sort unique connections by protocol for the target host and filtered host

    Args
    ----------
    streams (list): select metadata for each stream/conversation
    targetHost: The target IP being analyzed
    filterHost: The host the target is communicating with

    Return
    -------
    seeds (list): unique streams for host pair labeled with protocol
    """
    seeds = []
    #TCP/UDP
    for stream in streams:
        if stream[0] == 'tcp':
            if stream[1] == targetHost and stream[3] == filterHost:
                srcIP = stream[1]
                srcPort = stream[2]
                destinationIP = stream[3]
                destinationPort = stream[4]
                protocol = stream[0]
                seed = (srcIP,srcPort,destinationIP,destinationPort,protocol)
                seeds.append(seed)
            elif stream[1] == filterHost and stream[3] == targetHost:
                srcIP = stream[3]
                srcPort = stream [4]
                destinationIP = stream[1]
                destinationPort = stream[2]
                protocol = stream[0]
                seed = (srcIP,srcPort,destinationIP,destinationPort,protocol)
                seeds.append(seed)
        elif stream[0] == "udp":
            if stream[1] == targetHost and stream[3] == filterHost:
                srcIP = stream[1]
                srcPort = stream[2]
                destinationIP = stream[3]
                destinationPort = stream[4]
                protocol = stream[0]
                seed = (srcIP,srcPort,destinationIP,destinationPort,protocol)
                seeds.append(seed)
            elif stream[1] == filterHost and stream[3] == targetHost:
                srcIP = stream[3]
                srcPort = stream[4]
                destinationIP = stream[1]
                destinationPort = stream[2]
                protocol = stream[0]
                seed = (srcIP,srcPort,destinationIP,destinationPort,protocol)
                seeds.append(seed)
        elif stream[0] == "icmp":
            if stream[1] == targetHost and stream[2] == filterHost:
                srcIP = stream[1]
                destinationIP = stream[2]
                protocol = stream[0]
                seed = (srcIP,destinationIP,protocol)
                seeds.append(seed)
            elif stream[1] == filterHost and stream[2] == targetHost:
                srcIP = stream[1]
                destinationIP = stream[2]
                protocol = stream[0]
                seed = (srcIP,destinationIP,protocol)
                seeds.append(seed)

    seeds = sorted(set(seeds))

    print(Fore.BLUE + '[' + Fore.WHITE + '-' + Fore.BLUE + ']' + Fore.GREEN + ' Mined ' +
    str(len(seeds)) + ' unqiue connections between %s and %s requiring ipFilter rules')%(targetHost, filterHost)
    print ""
    return seeds


def createRules(targetHost, filterHost, seeds):
    """
    Create rules statements based on unique conversations per protocol

    Args
    ----------
    seeds (list): unique streams for host pair labeled with protocol
    targetHost: The target IP being analyzed
    filterHost: The host the target is communicating with

    Return
    -------
    n/a
    """
    rulesFile = open("/root/Desktop/ipFilter.txt", 'a')
    rulesCounter = 0

    for entry in seeds:
        #tcp
        if entry[-1] == 'tcp' and entry[0] == targetHost and entry[2] == filterHost:
            rulesFile.write("pass out quick proto tcp from %s port = %s to %s port = %s keep state\n" % (entry[0], entry[1], entry[2], entry[3]))
            rulesCounter = rulesCounter + 1
        elif entry[-1] == 'tcp' and entry[0] == filterHost and entry[2] == targetHost:
            rulesFile.write("pass in quick proto tcp from %s port = %s to %s port = %s keep state\n" % (entry[0], entry[1], entry[2], entry[3]))
            rulesCounter = rulesCounter + 1

        #udp
        if entry[-1] == 'udp' and entry[0] == targetHost and entry[2] == filterHost:
            rulesFile.write("pass out quick proto udp from %s port = %s to %s port = %s keep state\n" % (entry[0], entry[1], entry[2], entry[3]))
            rulesCounter = rulesCounter + 1
        elif entry[-1] == 'udp' and entry[0] == filterHost and entry[2] == targetHost:
            rulesFile.write("pass in quick proto udp from %s port = %s to %s port = %s keep state\n" % (entry[0], entry[1], entry[2], entry[3]))
            rulesCounter = rulesCounter + 1

        #icmp
        if entry[-1] == 'icmp' and entry[0] == targetHost and entry[2] == filterHost:
            rulesFile.write("pass out quick proto icmp from %s to %s keep state\n" % (entry[1], entry[2]))
            rulesCounter = rulesCounter + 1
        elif entry[-1] == 'icmp' and entry[0] == filterHost and entry[2] == targetHost:
            rulesFile.write("pass in quick proto icmp from %s to %s keep state\n" % (entry[1], entry[2]))
            rulesCounter = rulesCounter + 1

    rulesFile.close()

    print(Fore.BLUE + '[' + Fore.WHITE + '-' + Fore.BLUE + ']' + Fore.GREEN + ' Created ' +
                                           str(rulesCounter) + ' icmp, tcp, and udp rule(s)')
    print ""


def base(streams, targetHost, filterHost):
    """
    Parse log data

    Args
    ----------
    streams (list): conversation data for all protocols and all hosts
    targetHost: The target IP being analyzed
    filterHost: The host the target is communicating with

    Return
    -------
    n/a
    """
    seeds = packetBucket(streams, targetHost, filterHost)
    createRules(targetHost, filterHost, seeds)
