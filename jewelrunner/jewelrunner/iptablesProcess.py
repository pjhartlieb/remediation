#!/usr/bin/python
#iptablesProcess.py

############################################################
#                                                          #
#                                                          #
#     [*] Ingesting logs and creating firewall rules       #
#         for ipTables                                     #
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

import random
import re
from colorama import Fore
from jewelrunner import iptablesSingle


def uniq(lst):
    """
     Sort and deduplicate list entries [2].

     Parameters
     ----------
     lst (list)

     Returns
     -------
     n/a
     """
    last = object()
    for item in lst:
        if item == last:
            continue
        yield item
        last = item


def sort_and_deduplicate(l):
    """
     Sort and deduplicate list entries [2].

     Parameters
     ----------
     l (list)

     Returns
     -------
     list (list): sorted and deduplicated list
     """
    return list(uniq(sorted(l, reverse=True)))


def yes_or_no(question):
    """
    Accept y/n response from user

    Parameters
    ----------
    question (string)

    Returns
    -------
    boolean
    """
    while "the answer is invalid":
        reply = str(raw_input(question+' (y/n): ')).lower().strip()
        if reply[:1] == 'y':
            return True
        if reply[:1] == 'n':
            return False
        else:
            return yes_or_no((Fore.BLUE + '[' + Fore.WHITE + 'e' + Fore.BLUE + ']' + Fore.GREEN + ' ERROR: Log file '
                                                                    'does not appear to be well formed. Proceed?'))

def is_valid_iptables_log(iptablesFile):
    """
    Select a random line from the iptables log. Verify format and structure. Proceed based on user selection.

    Parameters
    ----------
    iptablesFile : iptables log file from RHEL system

    Returns
    -------
    n/a
    """
    address = None
    pointer = None

    line = random.choice(open(iptablesFile).readlines())

    match = re.search('SRC=[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', line)
    if match:
        address = match.group(0)

    match = re.search('iptables:', line)
    if match:
        pointer=match.group(0)

    if address and pointer:
        print(Fore.BLUE + '[' + Fore.WHITE + '-' + Fore.BLUE + ']' + Fore.GREEN + ' Iptables log file appears to be '
                                                                                  'well-formed')
    else:

        question = (Fore.BLUE + '[' + Fore.WHITE + 'e' + Fore.BLUE + ']' + Fore.GREEN + ' ERROR: Log file does not'
                                                                                  ' appear to be well formed. Proceed?')
        response=yes_or_no(question)

        if not response:
            print ""
            exit()

    print""


def readData(data):
    """
    Open log file for operations

    Args
    ----------
    data (str): file passed at the command line

    Return
    -------
    data (list): Line by line list for the log file entries
    """
    f=open(data, 'rb')
    dataEntries = f.read().splitlines()
    return dataEntries


def preProc(dataEntries):
    """
    Sort conversations by protocol

    Args
    ----------
    dataEntries (list): line by line entries for the log file

    Return
    -------
    streams (list): select metadata for each stream/conversation according to protocol
    """
    streams = []

    print(
        Fore.BLUE + '[' + Fore.WHITE + '-' + Fore.BLUE + ']' + Fore.GREEN + ' Pre-processing ' +
                                            str(len(dataEntries)) + ' log entries')
    print ""
    tcpCounter = 0
    udpCounter = 0
    icmpCounter = 0

    for datum in dataEntries:
        match = re.search("PROTO=([A-Z]{3,4})\s", datum)
        if match:
            protoP= match.group(1) #only the first matching group in parentheses. Not the \s which is
                                   # in group(0)

            #TCP. Only capture packets and write seeds where the SYN flag is set. Conversations getting originated.
            if protoP == "TCP":
                srcIP = None
                srcPort = None
                dstIP = None
                dstPort = None
                cFlag = None
                interface = None
                iot = None

                match = re.search('SRC=[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', datum)
                if match:
                    srcSIP= match.group(0)
                    srcIP = srcSIP.rpartition('=')[2]

                match = re.search('DST=[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', datum)
                if match:
                    dstSIP= match.group(0)
                    dstIP = dstSIP.rpartition('=')[2]

                match = re.search('SPT=[0-9]{1,5}', datum)
                if match:
                    srcSPort = match.group(0)
                    srcPort = srcSPort.rpartition('=')[2]
                    srcPort = int(srcPort)

                match = re.search('DPT=[0-9]{1,5}', datum)
                if match:
                    dstSPort = match.group(0)
                    dstPort = dstSPort.rpartition('=')[2]
                    dstPort = int(dstPort)

                match_1 = re.search('\s(SYN)\s', datum)
                match_2 = re.search('\s(ACK)\s', datum)
                if match_1 and not match_2:
                    cFlag = match_1.group(1)

                match_1 = re.search('IN=[a-z0-9]{3,4}\s', datum)
                match_2 = re.search('OUT=[a-z0-9]{3,4}\s', datum)
                if match_1 and not match_2:
                    interfaceS = match_1.group(0)
                    interface = interfaceS.rpartition('=')[2]
                    iot = 'in'
                elif match_2 and not match_1:
                    interfaceS = match_2.group(0)
                    interface = interfaceS.rpartition('=')[2]
                    iot = 'out'

                tcpCounter = tcpCounter + 1

                # Only append streams where a connection is initiated. ie. SYN flag is set
                if protoP and srcIP and srcPort and dstIP and dstPort and cFlag and interface:
                    stream = (protoP,srcIP,srcPort,dstIP,dstPort,interface,iot)
                    streams.append(stream)

            #UDP. No way to know who initiated the conversation. Assumptions must be made later.
            if protoP == "UDP":
                srcIP = None
                srcPort = None
                dstIP = None
                dstPort = None
                interface = None
                iot = None

                match = re.search('SRC=[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', datum)
                if match:
                    srcSIP= match.group(0)
                    srcIP = srcSIP.rpartition('=')[2]

                match = re.search('DST=[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', datum)
                if match:
                    dstSIP= match.group(0)
                    dstIP = dstSIP.rpartition('=')[2]

                match = re.search('SPT=[0-9]{1,5}', datum)
                if match:
                    srcSPort = match.group(0)
                    srcPort = srcSPort.rpartition('=')[2]
                    srcPort = int(srcPort)

                match = re.search('DPT=[0-9]{1,5}', datum)
                if match:
                    dstSPort = match.group(0)
                    dstPort = dstSPort.rpartition('=')[2]
                    dstPort = int(dstPort)

                match_1 = re.search('IN=[a-z0-9]{3,4}\s', datum)
                match_2 = re.search('OUT=[a-z0-9]{3,4}\s', datum)
                if match_1 and not match_2:
                    interfaceS = match_1.group(0)
                    interface = interfaceS.rpartition('=')[2]
                    iot='in'
                elif match_2 and not match_1:
                    interfaceS = match_2.group(0)
                    interface = interfaceS.rpartition('=')[2]
                    iot='out'

                udpCounter = udpCounter + 1

                if protoP and srcIP and srcPort and dstIP and dstPort and interface:
                    stream = (protoP,srcIP,srcPort,dstIP,dstPort, interface, iot)
                    streams.append(stream)


    print('\t' +
        Fore.BLUE + '[' + Fore.WHITE + '-' + Fore.BLUE + ']' + Fore.GREEN + ' Mined ' +
                                            str(tcpCounter) + ' tcp entries')

    print('\t' +
        Fore.BLUE + '[' + Fore.WHITE + '-' + Fore.BLUE + ']' + Fore.GREEN + ' Mined ' +
                                            str(udpCounter) + ' udp entries')
    print ""

    return streams


def packetBucket(streams):
    """
    Sort unique connections by protocol

    Args
    ----------
    streams (list): select metadata for each stream/conversation

    Return
    -------
    seeds (list): unique streams per protocol
    """
    seeds = []
    streamOrphans = []
    highportWarnings = []

    #TCP/UDP
    for stream in streams:
        if stream[0] == "TCP":
        #Simplified since every seed is for SYN packets only. The originators of the conversation is known
            if int(stream[4]) >= 30000 and int(stream[2]) >= 30000:
                highportWarnings.append(stream)
            else:
                srcIP = stream[1]
                destinationIP = stream[3]
                destinationPort = stream[4]
                protocol = stream[0]
                interface = stream[5]
                iot = stream[6]
                seed = (srcIP, destinationIP , destinationPort , protocol, interface)
                seeds.append(seed)

        elif stream[0] == "UDP":
            if int(stream[4]) >= 30000 and int(stream[2]) >= 30000:
                highportWarnings.append(stream)
            #This ASSUMES that the higher port originated the conversation. Array is subsequently built.
            elif int(stream[2]) > int(stream[4]) and int(stream[2]) >= 1023:
                srcIP = stream[1]
                destinationIP = stream[3]
                destinationPort = stream[4]
                interface = stream[5]
                iot = stream[6]
                protocol = stream[0]
                seed = (srcIP, destinationIP, destinationPort, protocol, interface)
                seeds.append(seed)
            #This ASSUMES that the higher port originated the conversation. Array is subsequently built.
            elif int(stream[4]) > int(stream[2]) and int(stream[4]) >= 1023:
                srcIP = stream[3]
                destinationIP = stream[1]
                destinationPort = stream[2]
                interface = stream[5]
                iot = stream[6]
                protocol = stream[0]
                seed = (srcIP, destinationIP, destinationPort, protocol, interface)
                seeds.append(seed)
            #If ports are equal then the originator is ASSUMED to be the SRC IP from the log entry
            elif int(stream[4]) == int(stream[2]):
                srcIP = stream[3]
                srcPort = stream[4]
                destinationIP = stream[1]
                destinationPort = stream[2]
                interface = stream[5]
                iot = stream[6]
                protocol = stream[0]
                seed = (srcIP, srcPort, destinationIP, destinationPort, protocol, interface)
                seeds.append(seed)
            #All other traffic is ASSUMED to be anamolous
            else:
                streamOrphans.append(stream)


    seeds = sorted(set(seeds))
    streamOrphans = sort_and_deduplicate(streamOrphans)
    highportWarnings = sort_and_deduplicate(highportWarnings)

    print(Fore.BLUE + '[' + Fore.WHITE + '-' + Fore.BLUE + ']' + Fore.GREEN + ' Mined ' +
                                            str(len(seeds)) + ' unique connections')
    print ""

    return seeds, streamOrphans, highportWarnings


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
        #tcp
        if entry[-2] == 'TCP' and entry[0] == target: #Target initiated the outbound connection
            rulesFile.write("# [-] " + "PORT " + str(entry[2]) + "\n")
            rulesFile.write("sudo iptables -A OUTPUT -o %s -p tcp -d %s --dport %s -m conntrack --ctstate NEW,"
                            "ESTABLISHED -j ACCEPT\n" % (entry[4], entry[1], entry[2]))
            rulesFile.write("sudo iptables -A INPUT -i %s -p tcp -s %s --sport %s -m conntrack --ctstate ESTABLISHED -j ACCEPT\n"
                            % (entry[4], entry[1], entry[2]))
            rulesFile.write("\n")
            rulesCounter = rulesCounter + 2

        elif entry[-2] == 'TCP' and entry[1] == target: #target receives inbound connection
            rulesFile.write("# [-] " + "PORT " + str(entry[2]) + "\n")
            rulesFile.write("sudo iptables -A INPUT -i %s -p tcp -s %s --dport %s -m conntrack --ctstate NEW,"
                            "ESTABLISHED -j ACCEPT\n" % (entry[4], entry[0], entry[2]))
            rulesFile.write("sudo iptables -A OUTPUT -o %s -p tcp --sport %s -d %s -m conntrack --ctstate ESTABLISHED -j ACCEPT\n"
                            % (entry[4], entry[2], entry[0]))
            rulesFile.write("\n")
            rulesCounter = rulesCounter + 2

        #udp
        if entry[-2] == 'UDP' and len(entry) == 5 and entry[0] == target: #Account for both to initiate connection if ports are equal
            rulesFile.write("# [-] " + "PORT " + str(entry[2]) + "\n")
            rulesFile.write("sudo iptables -A OUTPUT -o %s -p udp -m udp -d %s --dport %s -j ACCEPT\n"
                            % (entry[4], entry[1], entry[2]))
            rulesFile.write("sudo iptables -A INPUT -i %s -p udp -m udp -s %s --sport %s -j ACCEPT\n"
                            % (entry[4], entry[1], entry[2]))
            rulesFile.write("\n")
            rulesCounter = rulesCounter + 2
        elif entry[-2] == 'UDP' and len(entry) == 5 and entry[1] == target:
            rulesFile.write("# [-] " + "PORT " + str(entry[2]) + "\n")
            rulesFile.write("sudo iptables -A INPUT -i %s -p udp -m udp -s %s --dport %s -j ACCEPT\n"
                            % (entry[4], entry[0], entry[2]))
            rulesFile.write("sudo iptables -A OUTPUT -i %s -p udp -m udp --sport %s -d %s -j ACCEPT\n"
                            % (entry[4], entry[2], entry[0]))
            rulesFile.write("\n")
            rulesCounter = rulesCounter + 2
        elif entry[-2] == 'UDP' and len(entry) == 6 and entry[0] == target: #Account for both to initiate connection if ports are equal
            rulesFile.write("# [-] " + "PORT " + str(entry[3]) + "\n")
            rulesFile.write("sudo iptables -A OUTPUT -o %s -p udp -m udp -d %s --dport %s -j ACCEPT\n"
                            % (entry[5], entry[2], entry[3]))
            rulesFile.write("sudo iptables -A INPUT -i %s -p udp -m udp -s %s --sport %s -j ACCEPT\n"
                            % (entry[5], entry[2], entry[3]))
            rulesFile.write("\n")
            rulesCounter = rulesCounter + 2
        elif entry[-2] == 'UDP' and len(entry) == 6 and entry[2] == target:
            rulesFile.write("# [-] " + "PORT " + str(entry[3]) + "\n")
            rulesFile.write("sudo iptables -A INPUT -i %s -p udp -m udp -s %s --dport %s -j ACCEPT\n"
                            % (entry[5], entry[0], entry[3]))
            rulesFile.write("sudo iptables -A OUTPUT -i %s -p udp -m udp --sport %s -d %s -j ACCEPT\n"
                            % (entry[5], entry[3], entry[0]))
            rulesFile.write("\n")
            rulesCounter = rulesCounter + 2

    rulesFile.close()

    print(Fore.BLUE + '[' + Fore.WHITE + '-' + Fore.BLUE + ']' + Fore.GREEN + ' Created ' +
                                           str(rulesCounter) + ' icmp, tcp, and udp rule(s) for ' + target)
    print ""


def orphanSummary(streamOrphans, highportWarnings):
    """
    Print out seeds that include high port to high port traffic

    Args
    ----------
    streamOrphans(list): collection of high port to high port seeds

    Return
    -------
    N/A
    """
    if streamOrphans:
        print(Fore.BLUE + '[' + Fore.WHITE + '-' + Fore.BLUE + ']' + Fore.GREEN + ' Harvested ' +
                                           str(len(streamOrphans)) + ' anomalous streams')
        print ""
        for orphan in streamOrphans:
            print orphan
        print ""
    if highportWarnings:
        print(Fore.BLUE + '[' + Fore.WHITE + '-' + Fore.BLUE + ']' + Fore.GREEN + ' Harvested ' +
              str(len(highportWarnings)) + ' streams that look like high port traffic')
        print ""
        for warning in highportWarnings:
            print warning
        print ""


def sortipTables(inputFile, ip, inputFilter, outputFile):
    """
    An iptableslog  file will be processed in 1 of 2 ways. If there is both an ip for the target (ip) and an ip for a
    specific host (inputFilter) then the log file will be parsed for conversations and rules will be created for these
    2 hosts only. If there is only a target ip, then the log file will be parsed for all conversations and all rules
    will be created.

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
    is_valid_iptables_log(inputFile)
    dataEntries = readData(inputFile)

    print(Fore.BLUE + '[' + Fore.WHITE + '-' + Fore.BLUE + ']' + Fore.GREEN + ' Analyzing file %s') % (inputFile)
    print ""
    print(Fore.BLUE + '[' + Fore.WHITE + '-' + Fore.BLUE + ']' + Fore.GREEN + ' Target(host) IP: %s') % (ip)
    print""

    if inputFilter:
       print(Fore.BLUE + '[' + Fore.WHITE + '-' + Fore.BLUE + ']' + Fore.GREEN + ' Filtered(host) IP: %s') % (inputFilter)
       print ""
       streams = preProc(dataEntries)
       iptablesSingle.base(streams, ip, inputFilter, outputFile)
    else:
       streams = preProc(dataEntries)
       seeds, streamOrphans, highportWarnings= packetBucket(streams)
       createRules(ip, seeds, outputFile)
       orphanSummary(streamOrphans, highportWarnings)
