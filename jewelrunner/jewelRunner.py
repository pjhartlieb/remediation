#!/usr/bin/python
#jewelRunner.py

############################################################
#                                                          #
#                                                          #
#    [*] Adopted from original scripts created by:         #
#        brifordwylie @ https://github.com/brifordwylie    #
#        RemiDesgrange @ https://github.com/RemiDesgrange  #
#        saylenty @ https://github.com/saylenty            #
#                                                          #
#    [*] Main                                              #
#                                                          #
#    [*] 2018.04.18                                        #
#          V0008                                           #
#          Black Lantern Security (BLS)                    #
#          @pjhartlieb                                     #
#                                                          #
#                                                          #
############################################################

"""
[*] REF
[1] https://github.com/kbandla/dpkt/blob/master/examples/print_packets.py
[2] http://www.commercialventvac.com/dpkt.html
[3] http://engineering-notebook.readthedocs.io/en/latest/engineering/dpkt.html
[4] https://jon.oberheide.org/blog/2008/10/15/dpkt-tutorial-2-parsing-a-pcap-file/
[5] http://dpkt.readthedocs.io/en/latest/print_icmp.html
[6] https://github.com/jeffsilverm/dpkt_doc/blob/master/decode_tcp_iterator_2.py
[7] http://patgardner.blogspot.com/2008/07/solaris-10-ipfilter.html
[8] https://gist.github.com/garrettdreyfus/8153571

[-] TBD
1. Give user the choice to create specific flavor of firewall rules using pcap contents
2. Filter out passive ftp traffic
3. Parse ipv6
4. Handle broadcast traffic
5. Add option for file output - DONE
6. Add feature that will make recommendations to consolidate rules from single IPs to VLANs
7. Add ephemeral cmd line switch to clean up ports
8. Remove redundancies. Create module for utility functions.

Jewelrunner is intended to ingest pcaps and/or log files, analyze ingress/egress traffic to a specific host, and create
host-based firewall rules AIX, Solaris, and Linux hosts
"""
import argparse
import os
import re
from colorama import Fore
from jewelrunner import flume

def is_valid_location(parser, arg):
    """
    Check if arg file already exists. Verify that the target directory is valid.

    Parameters
    ----------
    parser : argparse object
    arg : str

    Returns
    -------
    arg
    """
    dir_path = os.path.dirname(os.path.realpath(arg))
    arg = os.path.abspath(arg)
    if  not os.path.isdir(dir_path):
        parser.error("The directory %s does not exist!" % dir_path)
    elif os.path.isfile(arg):
        parser.error("The file %s already exists!" % arg)
    else:
        print(Fore.BLUE + '[' + Fore.WHITE + '-' + Fore.BLUE + ']' + Fore.GREEN + ' Output will be'
                                                                                  ' written to %s' %arg)
        print
        ""
    return arg


def is_valid_file(parser, arg):
    """
    Check if arg is a valid file that already exists on the file system.

    Parameters
    ----------
    parser : argparse object
    arg : str

    Returns
    -------
    arg
    """
    arg = os.path.abspath(arg)
    if not os.path.exists(arg):
        parser.error("The file %s does not exist!" % arg)
    else:
        print(Fore.BLUE + '[' + Fore.WHITE + '-' + Fore.BLUE + ']' + Fore.GREEN + ' Input file exists')
        print
        ""
        return arg


def is_valid_input(parser, arg):
    """
    Check if arg is a valid input type. Valid type are ipfilter, ipsec, and pcap.

    Parameters
    ----------
    parser : argparse object
    arg : str

    Returns
    -------
    arg
    """
    match = re.match('ipfilter|ipsec|pcap|iptables', arg)
    if match:
        print(Fore.BLUE + '[' + Fore.WHITE + '-' + Fore.BLUE + ']' + Fore.GREEN + ' Input option is valid')
        print ""
        return arg
    else:
        parser.error("%s is not a valid input option" % arg)


def is_valid_ip(parser, arg):
    """
    Check if arg is a valid IP address.

    Parameters
    ----------
    parser : argparse object
    arg : str

    Returns
    -------
    arg
    """
    addr = arg
    a = addr.split('.')
    if len(a) != 4:
        parser.error("%s is not a valid IP address" % addr)
    for x in a:
        if not x.isdigit():
            parser.error("%s is not a valid IP address" % addr)
        i = int(x)
        if i < 0 or i > 255:
            parser.error("%s is not a valid IP address" % addr)
    return addr


def get_args():
    """
     Retrieve command line arguments.

     Parameters
     ----------
     n/a

     Returns
     -------
     ip (string): target IP address being examined
     inputFile (string): pcap or log file to be parsed
     inputType (string): specify the input file type
     """
    # Assign description to the help doc
    parser = argparse.ArgumentParser(
        description='Parse and summarize network traffic for a specific target host.')
    # Add arguments
    requiredNamed = parser.add_argument_group('required named arguments')
    requiredNamed.add_argument('-f', '--file',
                        dest="filename",
                        type=lambda x: is_valid_file(parser, x),
                        help='Full path to input file',
                        required=True,
                        metavar='')
    requiredNamed.add_argument('-io', '--input',
                        dest="input",
                        type=lambda x: is_valid_input(parser, x),
                        help='Input file type. pcap files ("pcap"), ipSec log files (ipsec), '
                             'ipFilter log files (ipfilter), and ipTables log files (iptables)',
                        metavar='',
                        required=True)
    requiredNamed.add_argument('-target', '--targetHost',
                        dest="ipAddress",
                        type=lambda x: is_valid_ip(parser, x),
                        help='Target host IP address',
                        metavar='',
                        required=True)
    optionalNamed = parser.add_argument_group('optional named arguments')
    optionalNamed.add_argument('-filter', '--filterHost',
                        dest="filterHost",
                        type=lambda x: is_valid_ip(parser, x),
                        help='Filter on this host IP address',
                        metavar='',
                        required=False)
    optionalNamed.add_argument('-of', '--outputFile',
                        dest="outputFile",
                        type=lambda x: is_valid_location(parser, x),
                        help='Write results to this file',
                        metavar='',
                        const='output.txt',
                        default='output.txt',
                        nargs='?',
                        required=False)

    # Array for all arguments passed to script
    args = parser.parse_args()
    # Assign args to variables
    ip = args.ipAddress
    inputFile = args.filename
    inputType = args.input
    inputFilter = args.filterHost
    if args.outputFile:
        outputFile = args.outputFile
    else:
        outputFile="output.txt"

    # Return all variable values
    return ip, inputFile, inputType, inputFilter, outputFile


if __name__ == '__main__':
    print ""
    ip, inputFile, inputType, inputFilter, outputFile = get_args()
    flume.runner(ip, inputFile, inputType, inputFilter, outputFile)