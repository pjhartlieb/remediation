#!/usr/bin/python
#ipsecSingle.py

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

# [*] REF
# [1] http://patgardner.blogspot.com/2008/07/solaris-10-ipfilter.html

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
        if stream[0] == "tcp":
            if stream[1] == targetHost and stream[3] == filterHost:
                srcIP = stream[1]
                srcPort = stream [2]
                destinationIP = stream[3]
                destinationPort = stream[4]
                protocol = stream[0]
                interface = stream[5]
                seed = (srcIP, srcPort, destinationIP , destinationPort , protocol, interface)
                seeds.append(seed)
            elif stream[1] == filterHost and stream[3] == targetHost:
                srcIP = stream[3]
                srcPort = stream [4]
                destinationIP = stream[1]
                destinationPort = stream[2]
                protocol = stream[0]
                interface = stream[5]
                seed = (srcIP, srcPort, destinationIP , destinationPort , protocol, interface)
                seeds.append(seed)
        elif stream[0] == "udp":
            if stream[1] == targetHost and stream[3] == filterHost:
                srcIP = stream[1]
                srcPort = stream[2]
                destinationIP = stream[3]
                destinationPort = stream[4]
                protocol = stream[0]
                interface = stream[5]
                seed = (srcIP, srcPort, destinationIP, destinationPort, protocol, interface)
                seeds.append(seed)
            elif stream[1] == filterHost and stream[3] == targetHost:
                srcIP = stream[3]
                srcPort = stream[4]
                destinationIP = stream[1]
                destinationPort = stream[2]
                protocol = stream[0]
                interface = stream[5]
                seed = (srcIP, srcPort, destinationIP, destinationPort, protocol, interface)
                seeds.append(seed)
        elif stream[0] == "icmp":
            if stream[1] == targetHost and stream[3] == filterHost:
                srcIP = stream[1]
                destinationIP = stream[2]
                icmpCode = stream[3]
                protocol = stream[0]
                interface = stream[4]
                seed = (srcIP, destinationIP, icmpCode, protocol, interface)
                seeds.append(seed)
            elif stream[1] == filterHost and stream[3] == targetHost:
                srcIP = stream[1]
                destinationIP = stream[2]
                icmpCode = stream[3]
                protocol = stream[0]
                interface = stream[4]
                seed = (srcIP, destinationIP, icmpCode, protocol, interface)
                seeds.append(seed)

    seeds = sorted(set(seeds))
    seeds = sorted(seeds, key=getKeyA)

    print(Fore.BLUE + '[' + Fore.WHITE + '-' + Fore.BLUE + ']' + Fore.GREEN + ' Mined ' +
        str(len(seeds)) + ' unique connections between %s and %s requiring ipsec rules')% (targetHost,
                                                                                           filterHost)
    print ""
    return seeds


def ipsecgenFilt(targetHost, filterHost, seeds):
    """
    Create GENFILT statements based on unique conversations per protocol

    Args
    ----------
    targetHost: The target IP being analyzed
    filterHost: The host the target is communicating with
    seeds (list): unique streams per protocol

    Return
    -------
    n/a
    """

    rulesFile = open("/root/Desktop/ipSec.txt", 'a')
    rulesCounter = 0

    for entry in seeds:
        #TCP
        #Outbound initiated from targetHost
        if entry[-2] == 'tcp' and entry[0] == targetHost and entry[2] == filterHost:
            rulesFile.write("# [-] " + "PORT " + str(entry[3]) + "\n")
            rulesFile.write( #OUT
                "$GENFILT -v 4 -a P -s " + entry[0] + " -d " + entry[2] + " -g N -c tcp -o eq -p " + str(entry[1]) + \
                                                    " -O eq -P " + str(entry[3]) + " -r L -w O -l N -f Y -i " + str(entry[-1]) + "-D unconfirmed \n")
            rulesFile.write( #IN
                "$GENFILT -v 4 -a P -s " + entry[2] + " -d " + entry[0] + " -g N -c tcp -o eq -p " + \
                                                    str(entry[3]) + " -O eq -P " + str(entry[1]) + " -r L -w I -l N -f Y -i " + str(entry[-1]) + "-D unconfirmed  \n")
            rulesFile.write("\n")
            rulesCounter = rulesCounter + 1
        #Inbound initiated by the filterHost
        elif entry[-2] == 'tcp' and entry[0] == filterHost and entry[2] == targetHost:
            rulesFile.write("# [-] PORT " + str(entry[3]) + "\n")
            rulesFile.write( #IN
                "$GENFILT -v 4 -a P -s " + entry[0] + " -d " + entry[2] + " -g N -c tcp -o gt -p " + str(entry[1]) + \
                                                    " -O eq -P " + str(entry[3]) + " -r L -w I -l N -f Y -i " + str(entry[-1]) + "-D unconfirmed \n")
            rulesFile.write( #OUT
                "$GENFILT -v 4 -a P -s " + entry[2] + " -d " + entry[0] + " -g N -c tcp -o eq -p " + \
                                                    str(entry[3]) + " -O eq -P " + str(entry[1]) + " -r L -w O -l N -f Y -i " + str(entry[-1]) + "-D unconfirmed  \n")
            rulesFile.write("\n")
            rulesCounter = rulesCounter + 1

        #UDP
        #Outbound initiated from targetHost
        if entry[-2] == 'udp' and entry[0] == targetHost and entry[2] == filterHost:
            rulesFile.write("# [-] " + "PORT " + str(entry[3]) + "\n")
            rulesFile.write( #OUT
                "$GENFILT -v 4 -a P -s " + entry[0] + " -d " + entry[2] + " -g N -c udp -o eq -p " + str(entry[1]) + \
                                                    " -O eq -P " + str(entry[3]) + " -r L -w O -l N -f Y -i " + str(entry[-1]) + "-D unconfirmed \n")
            rulesFile.write( #IN
                "$GENFILT -v 4 -a P -s " + entry[2] + " -d " + entry[0] + " -g N -c udp -o eq -p " + \
                                                    str(entry[3]) + " -O eq -P " + str(entry[1]) + " -r L -w I -l N -f Y -i " + str(entry[-1]) + "-D unconfirmed  \n")
            rulesFile.write("\n")
            rulesCounter = rulesCounter + 1
        #Inbound initiated by the filterHost
        elif entry[-2] == 'udp' and entry[0] == filterHost and entry[2] == targetHost:
            rulesFile.write("# [-] PORT " + str(entry[3]) + "\n")
            rulesFile.write( #IN
                "$GENFILT -v 4 -a P -s " + entry[0] + " -d " + entry[2] + " -g N -c udp -o gt -p " + str(entry[1]) + \
                                                    " -O eq -P " + str(entry[3]) + " -r L -w I -l N -f Y -i " + str(entry[-1]) + "-D unconfirmed \n")
            rulesFile.write( #OUT
                "$GENFILT -v 4 -a P -s " + entry[2] + " -d " + entry[0] + " -g N -c udp -o eq -p " + \
                                                    str(entry[3]) + " -O eq -P " + str(entry[1]) + " -r L -w O -l N -f Y -i " + str(entry[-1]) + "-D unconfirmed  \n")
            rulesFile.write("\n")
            rulesCounter = rulesCounter + 1

        #ICMP
        if entry[-2] == 'icmp' and entry[0] == targetHost and entry[1] == filterHost:
            rulesFile.write( #OUT
                "$GENFILT -v 4 -a P -s " + entry[0] + " -d " + entry[1] + " -g N "
                            "-c icmp -r L -w O -l N -f Y -i " + str(entry[4]) + " -D unconfirmed  \n")
            rulesFile.write("\n")
            rulesCounter = rulesCounter + 1
        elif entry[-2] == 'icmp' and entry[0] == filterHost and entry[1] == targetHost:
            rulesFile.write( #IN
                "$GENFILT -v 4 -a P -s " + entry[0] + " -d " + entry[1] + " -g N "
                            "-c icmp -r L -w I -l N -f Y -i " + str(entry[4]) + " -D unconfirmed  \n")
            rulesFile.write("\n")
            rulesCounter = rulesCounter + 1

    rulesFile.close()

    print(Fore.BLUE + '[' + Fore.WHITE + '-' + Fore.BLUE + ']' + Fore.GREEN + ' Created ' +
                                           str(rulesCounter) + ' icmp, tcp, and udp rule(s)')
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
    n/arm ipS
    """
    seeds = packetBucket(streams, targetHost, filterHost)
    ipsecgenFilt(targetHost, filterHost, seeds)