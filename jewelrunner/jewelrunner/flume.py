#!/usr/bin/python
#flume.py

############################################################
#                                                          #
#                                                          #
#    [*] Route processing request                          #
#                                                          #
#                                                          #
#    [*] 2018.04.18                                        #
#          V0003                                           #
#          Black Lantern Security (BLS)                    #
#          @pjhartlieb                                     #
#                                                          #
#                                                          #
############################################################

from jewelrunner import ipfilterProcess, pcapProcess, ipsecProcess, iptablesProcess


def runner(ip, inputFile, inputType, inputFilter, outputFile):
    """
     Shuttle files and parameters for processing

     Parameters
     ----------
     ip (string): target IP address being examined
     inputFilter (string): filter on conversations with IP for this IP address
     inputFile (string): pcap or firewall log file to be parsed
     inputType (string): specify the input file type (pcap, ipfilter, ipsec, iptables)

     Returns
     -------
     n/a
     """

    # shuttle input to the appropriate module
    if inputType == 'pcap':
        pcapProcess.sortPcap(inputFile, ip, inputFilter)

    elif inputType == 'ipfilter':
        ipfilterProcess.sortipFilter(inputFile, ip, inputFilter, outputFile)

    elif inputType == 'ipsec':
        ipsecProcess.sortipSec(inputFile, ip, inputFilter, outputFile)

    elif inputType == 'iptables':
        iptablesProcess.sortipTables(inputFile, ip, inputFilter, outputFile)