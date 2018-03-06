#!/usr/bin/python
#flume.py

############################################################
#                                                          #
#                                                          #
#    [*] Route processing request                          #
#                                                          #
#                                                          #
#    [*] 2018.03.05                                        #
#          V0002                                           #
#          Black Lantern Security (BLS)                    #
#          @pjhartlieb                                     #
#                                                          #
#                                                          #
############################################################

from jewelrunner import ipfilterProcess, pcapProcess, ipsecProcess


def runner(ip, inputFile, inputType, inputFilter):
    """
     Shuttle files and parameters for processing

     Parameters
     ----------
     ip (string): target IP address being examined
     inputFilter (string): filter on conversations with IP for this IP address
     inputFile (string): pcap or log file to be parsed
     inputType (string): specify the input file type

     Returns
     -------
     n/a
     """

    # shuttle input to the appropriate module
    if inputType == 'pcap':
        pcapProcess.sortPcap(inputFile, ip, inputFilter)

    elif inputType == 'ipfilter':
        ipfilterProcess.sortipFilter(inputFile, ip, inputFilter)

    elif inputType == 'ipsec':
        ipsecProcess.sortipSec(inputFile, ip, inputFilter)