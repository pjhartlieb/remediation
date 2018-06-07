#!/usr/bin/python
# ipsecProcess.py

############################################################
#                                                          #
#                                                          #
#    [-] Ingesting logs and Creating firewall rules        #
#        for IPSec                                         #
#                                                          #
#    [-] Tested with:                                      #
#           /var/log/ipsec.log                             #
#           AIX version 7100-04-04-1717                    #
#           ipSec version bos.net.ipsec.rte 7.1.4.31       #
                                                           #
#    [-] 2018.04.18                                        #
#          V0003                                           #
#          Black Lantern Security (BLS)                    #
#          @pjhartlieb                                     #
#                                                          #
#                                                          #
############################################################

# [-] REF
# [1] http://patgardner.blogspot.com/2008/07/solaris-10-ipfilter.html
# [2] https://web.stanford.edu/~ssklar/articles/ipsec-filtering.html
# [4] https://stackoverflow.com/questions/13464152/typeerror-unhashable-type-list-when-using-built-in-set-function

import random
import re
from colorama import Fore
from jewelrunner import ipsecSingle


def uniq(lst):
    """
     Sort and deduplicate list entries [4].

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
     Sort and deduplicate list entries [4].

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


def is_valid_ipsec_log(ipsecFile):
    """
    Select a random line from the ipsec log. Verify format and structure. Proceed based on user selection.

    Parameters
    ----------
    ipsecFile : ipsec logfile from AIX system

    Returns
    -------
    n/a
    """
    srcIP = None
    dstIP = None
    logtype = None

    line = random.choice(open(ipsecFile).readlines())

    match = re.search('S\:[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', line)
    if match:
        srcSIP = match.group(0)
        srcIP = srcSIP.rpartition(':')[2]

    match = re.search('D\:[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', line)
    if match:
        dstSIP = match.group(0)
        dstIP = dstSIP.rpartition(':')[2]

    match= re.search('ipsec_logd', line)
    if match:
        logtype=match.group(0)

    if srcIP and dstIP and logtype:
        print(Fore.BLUE + '[' + Fore.WHITE + '-' + Fore.BLUE + ']' + Fore.GREEN + ' Ipsec log file appears to be '
                                                                                  'well-formed')
    else:

        question = (Fore.BLUE + '[' + Fore.WHITE + 'e' + Fore.BLUE + ']' + Fore.GREEN + ' ERROR: Log file does not '
                                                                                  'appear to be well formed. Proceed?')
        response=yes_or_no(question)

        if not response:
            print ""
            exit()

    print""


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
        match = re.search("P\:([a-z]{3,4})\s", datum)
        if match:
            protoP= match.group(1) #only the first matching group in parentheses. Not the \s which is
                                   # in group(0)
            proto = protoP.rpartition(':')[2]

            #TCP
            if proto == "tcp":
                match = re.search('S\:[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', datum)
                srcSIP= match.group(0)
                srcIP = srcSIP.rpartition(':')[2]

                match = re.search('D\:[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', datum)
                dstSIP= match.group(0)
                dstIP = dstSIP.rpartition(':')[2]

                match = re.search('SP\:[0-9]{1,5}', datum)
                srcSPort= match.group(0)
                srcPort = srcSPort.rpartition(':')[2]
                srcPort = int(srcPort)

                match = re.search('DP\:[0-9]{1,5}', datum)
                dstSPort = match.group(0)
                dstPort = dstSPort.rpartition(':')[2]
                dstPort = int(dstPort)

                match = re.search('I\:[0-9a-z]{3,3} ', datum)
                interface = match.group(0)
                interface = interface.rpartition(':')[2]
                interface = str(interface)

                tcpCounter = tcpCounter + 1

                stream = [proto,srcIP,srcPort,dstIP,dstPort,interface]
                streams.append(stream)

            #UDP
            if proto == "udp":
                match = re.search('S\:[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', datum)
                srcSIP= match.group(0)
                srcIP = srcSIP.rpartition(':')[2]

                match = re.search('D\:[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', datum)
                dstSIP= match.group(0)
                dstIP = dstSIP.rpartition(':')[2]

                match = re.search('SP\:[0-9]{1,5}', datum)
                srcSPort= match.group(0)
                srcPort = srcSPort.rpartition(':')[2]
                srcPort = int(srcPort)

                match = re.search('DP\:[0-9]{1,5}', datum)
                dstSPort = match.group(0)
                dstPort = dstSPort.rpartition(':')[2]
                dstPort = int(dstPort)

                match = re.search('I\:[0-9a-z]{1,4} ', datum)
                interface = match.group(0)
                interface = interface.rpartition(':')[2]
                interface = str(interface)

                udpCounter = udpCounter + 1

                stream = [proto,srcIP,srcPort,dstIP,dstPort,interface]
                streams.append(stream)

            #ICMP
            if proto == "icmp":
                match = re.search('S\:[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', datum)
                srcSIP= match.group(0)
                srcIP = srcSIP.rpartition(':')[2]

                match = re.search('D\:[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', datum)
                dstSIP= match.group(0)
                dstIP = dstSIP.rpartition(':')[2]

                match = re.search('T\:[0-9]{1,3}', datum)
                icmpcodeS = match.group(0)
                icmpCode = icmpcodeS.rpartition(':')[2]

                match = re.search('I\:[0-9a-z]{1,4} ', datum)
                interface = match.group(0)
                interface = interface.rpartition(':')[2]
                interface = str(interface)

                icmpCounter = icmpCounter + 1

                stream = [proto,srcIP,dstIP,icmpCode,interface]
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
    #This makes assumptions about the hosts role in the conversation based on port
    for stream in streams:
        if stream[0] == "tcp":
            if int(stream[4]) >= 30000 and int(stream[2]) >= 30000:
                highportWarnings.append(stream)
            elif (int(stream[2]) > int(stream[4])) and int(stream[2]) >= 1023:
                srcIP = stream[1]
                destinationIP = stream[3]
                destinationPort = stream[4]
                protocol = stream[0]
                interface = stream[5]
                seed = (srcIP, destinationIP , destinationPort , protocol, interface)
                seeds.append(seed)
            elif int(stream[4]) > int(stream[2]) and int(stream[4]) >= 1023:
                srcIP = stream[3]
                destinationIP = stream[1]
                destinationPort = stream[2]
                protocol = stream[0]
                interface = stream[5]
                seed = (srcIP, destinationIP , destinationPort , protocol, interface)
                seeds.append(seed)
            elif int(stream[4]) == int(stream[2]):
                srcIP = stream[3]
                srcPort = stream[4]
                destinationIP = stream[1]
                destinationPort = stream[2]
                protocol = stream[0]
                interface = stream[5]
                seed = (srcIP, srcPort, destinationIP, destinationPort, protocol, interface)
                seeds.append(seed)
            else:
                streamOrphans.append(stream)

        elif stream[0] == "udp":
            if int(stream[4]) >= 30000 and int(stream[2]) >= 30000:
                highportWarnings.append(stream)
            elif int(stream[2]) > int(stream[4]) and int(stream[2]) >= 1023:
                srcIP = stream[1]
                destinationIP = stream[3]
                destinationPort = stream[4]
                protocol = stream[0]
                interface = stream[5]
                seed = (srcIP, destinationIP, destinationPort, protocol, interface)
                seeds.append(seed)
            elif int(stream[4]) > int(stream[2]) and int(stream[4]) >= 1023:
                srcIP = stream[3]
                destinationIP = stream[1]
                destinationPort = stream[2]
                protocol = stream[0]
                interface = stream[5]
                seed = (srcIP, destinationIP, destinationPort, protocol, interface)
                seeds.append(seed)
            elif int(stream[4]) == int(stream[2]):
                srcIP = stream[3]
                srcPort = stream[4]
                destinationIP = stream[1]
                destinationPort = stream[2]
                protocol = stream[0]
                interface = stream[5]
                seed = (srcIP, srcPort, destinationIP, destinationPort, protocol, interface)
                seeds.append(seed)
            else:
                streamOrphans.append(stream)

        elif stream[0] == "icmp":
            srcIP = stream[1]
            destinationIP = stream[2]
            icmpCode = stream[3]
            protocol = stream[0]
            interface = stream[4]
            seed = (srcIP, destinationIP, icmpCode, protocol, interface)
            seeds.append(seed)

    seeds = sorted(set(seeds))
    seeds = sorted(seeds, key=getKeyA)
    streamOrphans = sort_and_deduplicate(streamOrphans)
    highportWarnings = sort_and_deduplicate(highportWarnings)

    print(Fore.BLUE + '[' + Fore.WHITE + '-' + Fore.BLUE + ']' + Fore.GREEN + ' Mined ' +
                                            str(len(seeds)) + ' unique connections')
    print ""
    return seeds, streamOrphans, highportWarnings


def ipsecgenFilt(targetIp, threads, outputFile):
    """
    Create GENFILT statements based on unique conversations per protocol

    Args
    ----------
    targetIp (string): the host for which rules are being created
    threads (list): unique streams/conversations that need host-based rules

    Return
    -------
    n/a
    """

    rulesFile = open(outputFile, 'a')
    rulesCounter = 0

    for entry in threads:
        #tcp
        if entry[-2] == 'tcp' and entry[1] == entry[3] and entry[2] == targetIp:
            rulesFile.write("# [-] " + "PORT " + str(entry[3]) + "\n")
            rulesFile.write( #IN
                "$GENFILT -v 4 -a P -s " + entry[0] + " -d " + entry[2] + " -g N -c tcp -o eq -p " +
                str(entry[1]) + " -O eq -P " + str(entry[3]) + " -r L -w I -l N -f Y -i "
                + str(entry[5]) + "-D unconfirmed \n")
            rulesFile.write( #OUT
                "$GENFILT -v 4 -a P -s " + entry[2] + " -d " + entry[0] + " -g N -c tcp -o eq -p " +
                str(entry[3]) + " -O eq -P " + str(entry[1])+ " -r L -w O -l N -f Y -i " + str(entry[5])
                + "-D unconfirmed  \n")
            rulesFile.write("\n")
            rulesCounter = rulesCounter + 1
        elif entry[-2] == 'tcp' and entry[1] == entry[3] and entry[0] == targetIp:
            rulesFile.write("# [-] " + "PORT " + str(entry[3]) + "\n")
            rulesFile.write( #OUT
                "$GENFILT -v 4 -a P -s " + entry[0] + " -d " + entry[2] + " -g N -c tcp -o eq -p " +
                str(entry[1]) + " -O eq -P " + str(entry[3]) + " -r L -w O -l N -f Y -i "
                + str(entry[5]) + "-D unconfirmed \n")
            rulesFile.write( #IN
                "$GENFILT -v 4 -a P -s " + entry[2] + " -d " + entry[0] + " -g N -c tcp -o eq -p " +
                str(entry[3]) + " -O eq -P " + str(entry[1])+ " -r L -w I -l N -f Y -i " + str(entry[5])
                + "-D unconfirmed  \n")
            rulesFile.write("\n")
            rulesCounter = rulesCounter + 1
        elif entry[-2] == 'tcp' and entry[1] == targetIp:
            rulesFile.write("# [-] " + "PORT " + str(entry[2]) + "\n")
            rulesFile.write( #IN
                "$GENFILT -v 4 -a P -s " + entry[0] + " -d " + entry[1] + " -g N -c tcp -o gt -p 1023 " \
                "-O eq -P " + str(entry[2]) + " -r L -w I -l N -f Y -i " + str(entry[4])
                + "-D unconfirmed \n")
            rulesFile.write( #OUT
                "$GENFILT -v 4 -a P -s " + entry[1] + " -d " + entry[0] + " -g N -c tcp -o eq -p " +
                str(entry[2]) + " -O gt -P 1023 -r L -w O -l N -f Y -i " + str(entry[4])
                + "-D unconfirmed  \n")
            rulesFile.write("\n")
            rulesCounter = rulesCounter + 1
        elif entry[-2] == 'tcp' and entry[0] == targetIp:
            rulesFile.write("# [-] PORT " + str(entry[2]) + "\n")
            rulesFile.write( #OUT
                "$GENFILT -v 4 -a P -s " + entry[0] + " -d " + entry[1] + " -g N -c tcp -o gt -p 1023 " \
                "-O eq -P " + str(entry[2]) + " -r L -w O -l N -f Y -i " + str(entry[4])
                + "-D unconfirmed  \n")
            rulesFile.write(  #IN
                "$GENFILT -v 4 -a P -s " + entry[1] + " -d " + entry[0] + " -g N -c tcp -o eq -p " +
                str(entry[2]) + " -O gt -P 1023 -r L -w I -l N -f Y -i " + str(entry[4])
                + "-D unconfirmed  \n")
            rulesFile.write("\n")
            rulesCounter = rulesCounter + 1

        #udp
        if entry[-2] == 'udp' and entry[1] == entry[3] and entry[2] == targetIp:
            rulesFile.write("# [-] " + "PORT " + str(entry[3]) + "\n")
            rulesFile.write( #IN
                "$GENFILT -v 4 -a P -s " + entry[0] + " -d " + entry[2] + " -g N -c udp -o eq -p " +
                str(entry[1]) + " -O eq -P " + str(entry[3]) + " -r L -w I -l N -f Y -i "
                + str(entry[5]) + "-D unconfirmed \n")
            rulesFile.write( #OUT
                "$GENFILT -v 4 -a P -s " + entry[2] + " -d " + entry[0] + " -g N -c udp -o eq -p " +
                str(entry[3]) + " -O eq -P " + str(entry[1])+ " -r L -w O -l N -f Y -i " + str(entry[5])
                + "-D unconfirmed  \n")
            rulesFile.write("\n")
            rulesCounter = rulesCounter + 1
        elif entry[-2] == 'udp' and entry[1] == entry[3] and entry[0] == targetIp:
            rulesFile.write("# [-] " + "PORT " + str(entry[3]) + "\n")
            rulesFile.write( #OUT
                "$GENFILT -v 4 -a P -s " + entry[0] + " -d " + entry[2] + " -g N -c udp -o eq -p " +
                str(entry[1]) + " -O eq -P " + str(entry[3]) + " -r L -w O -l N -f Y -i "
                + str(entry[5]) + "-D unconfirmed \n")
            rulesFile.write( #IN
                "$GENFILT -v 4 -a P -s " + entry[2] + " -d " + entry[0] + " -g N -c udp -o eq -p " +
                str(entry[3]) + " -O eq -P " + str(entry[1])+ " -r L -w I -l N -f Y -i " + str(entry[5])
                + "-D unconfirmed  \n")
            rulesFile.write("\n")
            rulesCounter = rulesCounter + 1
        elif entry[-2] == 'udp' and entry[1] == targetIp:
            rulesFile.write("# [-] " + "PORT " + str(entry[2]) + "\n")
            rulesFile.write( #IN
                "$GENFILT -v 4 -a P -s " + entry[0] + " -d " + entry[1] + " -g N -c udp -o gt -p 1023 " \
                "-O eq -P " + str(entry[2]) + " -r L -w I -l N -f Y -i " + str(entry[4])
                + "-D unconfirmed  \n")
            rulesFile.write( #OUT
                "$GENFILT -v 4 -a P -s " + entry[1] + " -d " + entry[0] + " -g N -c udp -o eq -p " + \
                str(entry[2]) + " -O gt -P 1023 -r L -w O -l N -f Y -i " + str(entry[4])
                + "-D unconfirmed  \n")
            rulesFile.write("\n")
            rulesCounter = rulesCounter + 1
        elif entry[-2] == 'udp' and entry[0] == targetIp:
            rulesFile.write("# [-] " + "PORT " + str(entry[2]) + "\n")
            rulesFile.write( #OUT
                "$GENFILT -v 4 -a P -s " + entry[0] + " -d " + entry[1] + " -g N -c udp -o gt -p 1023 " \
                "-O eq -P " + str(entry[2]) + " -r L -w O -l N -f Y -i " + str(entry[4])
                + "-D unconfirmed  \n")
            rulesFile.write(  #IN
                "$GENFILT -v 4 -a P -s " + entry[1] + " -d " + entry[0] + " -g N -c udp -o eq -p " + \
                str(entry[2]) + " -O gt -P 1023 -r L -w I -l N -f Y -i " + str(entry[4])
                + "-D unconfirmed  \n")
            rulesFile.write("\n")
            rulesCounter = rulesCounter + 1

        #icmp
        if entry[-2] == 'icmp' and entry[0] == targetIp:
            rulesFile.write( #OUT
                "$GENFILT -v 4 -a P -s " + entry[0] + " -d " + entry[1] + " -g N "
                            "-c icmp -r L -w O -l N -f Y -i " + str(entry[4]) + " -D unconfirmed  \n")
            rulesFile.write("\n")
            rulesCounter = rulesCounter + 1
        elif entry[-2] == 'icmp' and entry[1] == targetIp:
            rulesFile.write( #IN
                "$GENFILT -v 4 -a P -s " + entry[0] + " -d " + entry[1] + " -g N "
                            "-c icmp -r L -w I -l N -f Y -i " + str(entry[4]) + " -D unconfirmed  \n")
            rulesFile.write("\n")
            rulesCounter = rulesCounter + 1

    rulesFile.close()

    print(Fore.BLUE + '[' + Fore.WHITE + '-' + Fore.BLUE + ']' + Fore.GREEN + ' Created ' +
                                           str(rulesCounter) + ' icmp, tcp, and udp rule(s) for ' + targetIp)
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


def sortipSec(inputFile, ip, inputFilter, outputFile):
    """
    An ipsec log  file will be processed in 1 of 2 ways. If there is both an ip for the target (ip) and an ip for a
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
    is_valid_ipsec_log(inputFile)
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
        ipsecSingle.base(streams, ip, inputFilter, outputFile)
    else:
        streams = preProc(dataEntries)
        seeds, streamOrphans, highportWarnings= packetBucket(streams)
        ipsecgenFilt(ip, seeds, outputFile)
        orphanSummary(streamOrphans, highportWarnings)