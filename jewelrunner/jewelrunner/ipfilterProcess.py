#!/usr/bin/python
#ipfilterProcess.py

############################################################
#                                                          #
#                                                          #
#     [*] Ingesting logs and creating firewall rules       #
#         for IPFilter                                     #
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
# [2] https://stackoverflow.com/questions/13464152/typeerror-unhashable-type-list-when-using-built-in-set-function

import random
import re
from colorama import Fore
from jewelrunner import ipfilterSingle


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

def is_valid_ipfilter_log(ipsecFile):
    """
    Select a random line from the ipfilter log. Verify format and structure. Proceed based on user selection.

    Parameters
    ----------
    ipsecFile : ipfilter log file from Solaris system

    Returns
    -------
    n/a
    """
    address = None
    pointer = None

    line = random.choice(open(ipsecFile).readlines())

    match = re.search('[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', line)
    if match:
        address = match.group(0)

    match = re.search('\-\>', line)
    if match:
        pointer=match.group(0)

    if address and pointer:
        print(Fore.BLUE + '[' + Fore.WHITE + 'c' + Fore.BLUE + ']' + Fore.GREEN + ' Ipfilter log file appears to be '
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
        match = re.search('tcp|udp|icmp', datum)
        if match:
            protoP= match.group(0)

            #TCP
            if protoP == "tcp":
                srcIP = None
                srcPort = None
                dstIp = None
                dstPort = None

                match = re.search('[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\,[0-9]{1,5} \-\>', datum)
                if match:
                    srcSIP= match.group(0)
                    srcIP = srcSIP.rpartition(',')[0]

                match = re.search('\-\> [0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\,[0-9]{1,5}', datum)
                if match:
                    dstSIP= match.group(0)
                    dstIP = dstSIP.rpartition(',')[0]
                    dstIP = dstIP.rpartition(' ')[2]

                match = re.search('[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\,[0-9]{1,5} \-\>', datum)
                if match:
                    srcSPort= match.group(0)
                    srcPort = srcSPort.rpartition(',')[2]
                    srcPort = srcPort.rpartition(' ')[0]
                    srcPort = int(srcPort)

                match = re.search('\-\> [0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\,[0-9]{1,5}', datum)
                if match:
                    dstSPort= match.group(0)
                    dstPort = dstSPort.rpartition(',')[2]
                    dstPort = int(dstPort)

                tcpCounter = tcpCounter + 1

                if protoP and srcIP and srcPort and dstSIP and dstPort:
                    stream = (protoP,srcIP,srcPort,dstIP,dstPort)
                    streams.append(stream)

            #UDP
            if protoP == "udp":
                srcIP = None
                srcPort = None
                dstIp = None
                dstPort = None
                match = re.search('[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\,[0-9]{1,5} \-\>', datum)
                if match:
                    srcSIP= match.group(0)
                    srcIP = srcSIP.rpartition(',')[0]

                match = re.search('\-\> [0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\,[0-9]{1,5}', datum)
                if match:
                    dstSIP= match.group(0)
                    dstIP = dstSIP.rpartition(',')[0]
                    dstIP = dstIP.rpartition(' ')[2]

                match = re.search('[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\,[0-9]{1,5} \-\>', datum)
                if match:
                    srcSPort= match.group(0)
                    srcPort = srcSPort.rpartition(',')[2]
                    srcPort = srcPort.rpartition(' ')[0]
                    srcPort = int(srcPort)

                match = re.search('\-\> [0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\,[0-9]{1,5}', datum)
                if match:
                    dstSPort= match.group(0)
                    dstPort = dstSPort.rpartition(',')[2]
                    dstPort = int(dstPort)

                udpCounter = udpCounter + 1

                if protoP and srcIP and srcPort and dstSIP and dstPort:
                    stream = (protoP,srcIP,srcPort,dstIP,dstPort)
                    streams.append(stream)

            #ICMP
            if protoP == "icmp":
                match = re.search('[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3} \-\>', datum)
                if match:
                    srcSIP= match.group(0)
                    srcIP = srcSIP.rpartition(' ')[0]

                match = re.search('\-\> [0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', datum)
                if match:
                    dstSIP= match.group(0)
                    dstIP = dstSIP.rpartition(' ')[2]

                icmpCounter = icmpCounter + 1

                if protoP and srcIP and dstIP:
                    stream = (protoP,srcIP,dstIP)
                    streams.append(stream)

    print('\t' +
        Fore.BLUE + '[' + Fore.WHITE + '-' + Fore.BLUE + ']' + Fore.GREEN + ' Mined ' +
                                            str(tcpCounter) + ' tcp entries')

    print('\t' +
        Fore.BLUE + '[' + Fore.WHITE + '-' + Fore.BLUE + ']' + Fore.GREEN + ' Mined ' +
                                            str(udpCounter) + ' udp entries')
    print('\t' +
        Fore.BLUE + '[' + Fore.WHITE + '-' + Fore.BLUE + ']' + Fore.GREEN + ' Mined ' +
                                            str(icmpCounter) + ' icmp entries')
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
        if stream[0] == "tcp":
            if int(stream[4]) >= 50000 and int(stream[2]) >= 50000:
                highportWarnings.append(stream)
            elif (int(stream[2]) > int(stream[4])) and int(stream[2]) >= 1023:
                srcIP = stream[1]
                destinationIP = stream[3]
                destinationPort = stream[4]
                protocol = stream[0]
                seed = (srcIP, destinationIP , destinationPort , protocol)
                seeds.append(seed)
            elif int(stream[4]) > int(stream[2]) and int(stream[4]) >= 1023:
                srcIP = stream[3]
                destinationIP = stream[1]
                destinationPort = stream[2]
                protocol = stream[0]
                seed = (srcIP, destinationIP , destinationPort , protocol)
                seeds.append(seed)
            elif int(stream[4]) == int(stream[2]):
                srcIP = stream[3]
                srcPort = stream[4]
                destinationIP = stream[1]
                destinationPort = stream[2]
                protocol = stream[0]
                seed = (srcIP, srcPort, destinationIP, destinationPort, protocol)
                seeds.append(seed)
            else:
                streamOrphans.append(stream)

        elif stream[0] == "udp":
            if int(stream[4]) >= 50000 and int(stream[2]) >= 50000:
                highportWarnings.append(stream)
            elif int(stream[2]) > int(stream[4]) and int(stream[2]) >= 1023:
                srcIP = stream[1]
                destinationIP = stream[3]
                destinationPort = stream[4]
                protocol = stream[0]
                seed = (srcIP, destinationIP, destinationPort, protocol)
                seeds.append(seed)
            elif int(stream[4]) > int(stream[2]) and int(stream[4]) >= 1023:
                srcIP = stream[3]
                destinationIP = stream[1]
                destinationPort = stream[2]
                protocol = stream[0]
                seed = (srcIP, destinationIP, destinationPort, protocol)
                seeds.append(seed)
            elif int(stream[4]) == int(stream[2]):
                srcIP = stream[3]
                srcPort = stream[4]
                destinationIP = stream[1]
                destinationPort = stream[2]
                protocol = stream[0]
                seed = (srcIP, srcPort, destinationIP, destinationPort, protocol)
                seeds.append(seed)
            else:
                streamOrphans.append(stream)

        elif stream[0] == "icmp":
            srcIP = stream[1]
            destinationIP = stream[2]
            protocol = stream[0]
            seed = (srcIP, destinationIP,protocol)
            seeds.append(seed)

    seeds = sorted(set(seeds))
    streamOrphans = sort_and_deduplicate(streamOrphans)
    highportWarnings = sort_and_deduplicate(highportWarnings)

    print(Fore.BLUE + '[' + Fore.WHITE + '-' + Fore.BLUE + ']' + Fore.GREEN + ' Mined ' +
                                            str(len(seeds)) + ' unique connections')
    print ""
    return seeds, streamOrphans, highportWarnings


def createRules(target, threads):
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
    rulesFile = open("/root/Desktop/ipFilter.txt", 'a')
    rulesCounter = 0

    for entry in threads:
        #tcp
        if entry[-1] == 'tcp' and entry[1] == entry[3] and entry[2] == target:
            rulesFile.write("pass in quick proto tcp from %s port = %s to %s port = %s keep state\n" % (entry[0],
                                                                            entry[1], entry[2], entry[3]))
            rulesCounter = rulesCounter + 1
        elif entry[-1] == 'tcp' and entry[1] == entry[3] and entry[0] == target:
            rulesFile.write("pass out quick proto tcp from %s port = %s to %s port = %s keep state\n" % (entry[0],
                                                                            entry[1], entry[2], entry[3]))
            rulesCounter = rulesCounter + 1
        elif entry[-1] == 'tcp' and entry[2] == target:
            rulesFile.write("pass in quick proto tcp from %s to %s port = %s keep state\n" % (entry[0],
                                                                            entry[1], entry[2]))
            rulesCounter = rulesCounter + 1
        elif entry[-1] == 'tcp' and entry[0] == target:
            rulesFile.write("pass out quick proto tcp from %s to %s port = %s keep state\n" % (entry[0],
                                                                            entry[1], entry[2]))
            rulesCounter = rulesCounter + 1
        #udp
        if entry[-1] == 'udp' and entry[1] == entry[3] and entry[2] == target:
            rulesFile.write("pass in quick proto udp from %s port = %s to %s port = %s keep state\n" % (entry[0],
                                                                            entry[1], entry[2], entry[3]))
            rulesCounter = rulesCounter + 1
        elif entry[-1] == 'udp' and entry[1] == entry[3] and entry[0] == target:
            rulesFile.write("pass out quick proto udp from %s port = %s to %s port = %s keep state\n" % (entry[0],
                                                                            entry[1], entry[2], entry[3]))
            rulesCounter = rulesCounter + 1
        elif entry[-1] == 'udp' and entry[2] == target:
            rulesFile.write("pass in quick proto udp from %s to %s port = %s keep state\n" % (entry[0],
                                                                            entry[1], entry[2]))
            rulesCounter = rulesCounter + 1
        elif entry[-1] == 'udp' and entry[0] == target:
            rulesFile.write("pass out quick proto udp from %s to %s port = %s keep state\n" % (entry[0],
                                                                            entry[1], entry[2]))
            rulesCounter = rulesCounter + 1

        #icmp
        if entry[-1] == 'icmp' and entry[1] == target:
            rulesFile.write("pass in quick proto icmp from %s to %s keep state\n" % (entry[0], entry[1]))
            rulesCounter = rulesCounter + 1
        elif entry[-1] == 'icmp' and entry[0] == target:
            rulesFile.write("pass out quick proto icmp from %s to %s keep state\n" % (entry[0], entry[1]))
            rulesCounter = rulesCounter + 1

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


def sortipFilter(inputFile, ip, inputFilter):
    """
    An ipfilter log  file will be processed in 1 of 2 ways. If there is both an ip for the target (ip) and an ip for a
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
    is_valid_ipfilter_log(inputFile)
    dataEntries = readData(inputFile)

    print(Fore.BLUE + '[' + Fore.WHITE + '-' + Fore.BLUE + ']' + Fore.GREEN + ' Analyzing file %s') % (inputFile)
    print
    ""
    print(Fore.BLUE + '[' + Fore.WHITE + '-' + Fore.BLUE + ']' + Fore.GREEN + ' Target(host) IP: %s') % (ip)
    print
    ""

    if inputFilter:
        print(Fore.BLUE + '[' + Fore.WHITE + '-' + Fore.BLUE + ']' + Fore.GREEN + ' Filtered(host) IP: %s') \
        % (inputFilter)
        print
        ""
        streams = preProc(dataEntries)
        ipfilterSingle.base(streams, ip, inputFilter)
    else:
        streams = preProc(dataEntries)
        seeds, streamOrphans, highportWarnings= packetBucket(streams)
        createRules(ip, seeds)
        orphanSummary(streamOrphans, highportWarnings)
