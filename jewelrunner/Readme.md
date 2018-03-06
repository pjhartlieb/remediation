# References

1. https://github.com/kbandla/dpkt/blob/master/examples/print_packets.py
2. http://www.commercialventvac.com/dpkt.html
3. http://engineering-notebook.readthedocs.io/en/latest/engineering/dpkt.html
4. https://jon.oberheide.org/blog/2008/10/15/dpkt-tutorial-2-parsing-a-pcap-file/
5. http://dpkt.readthedocs.io/en/latest/print_icmp.html
6. https://github.com/jeffsilverm/dpkt_doc/blob/master/decode_tcp_iterator_2.py
7. http://patgardner.blogspot.com/2008/07/solaris-10-ipfilter.html
8. https://gist.github.com/garrettdreyfus/8153571
9. http://patgardner.blogspot.com/2008/07/solaris-10-ipfilter.html
10. https://stackoverflow.com/questions/13464152/typeerror-unhashable-type-list-when-using-built-in-set-function
11. https://web.stanford.edu/~ssklar/articles/ipsec-filtering.html
12. http://www.unisys.com/offerings/security-solutions/unisys-stealth-products-and-services
13. https://www.illumio.com/home

# JewelRunner

JewelRunner is intended to quickly analyze tcp/ip traffic for a target host and create host-based firewall rules in support of  micro segmentation activities. In its current form it will:

* Parse pcap files and summarize tcp/ip traffic to and from a target IP;
* Parse ipFilter (Solaris) log files and generate firewall rules; and
* Parse ipSec (AIX) logs and generate firewall rules.

JewelRunner was built and tested with Python 2.7.14+

## Setup

The set-up is relatively simple. The required modules may be installed using the command below

*pip install -r /path/to/requirements.txt*

## Usage

Parse pcap file and analyze traffic for target IP 10.10.10.1

*./jewelRunner.py -f /path/to/file.pcap -io pcap -target 10.10.10.1*

Parse pcap file and analyze traffic between target IP 10.10.10.1 and 10.10.10.2

*./jewelRunner.py -f /path/to/file.pcap -io pcap -target 10.10.10.1 -filter 10.10.10.2*

Parse ipFilter log for target IP 10.10.10.1 and create host-based firewall rule set

*./jewelRunner.py -f /path/to/ipfilter.log -io ipfilter -target 10.10.10.1*

Parse ipFilter log for target IP 10.10.10.1, isolate entries for 10.10.10.2 and create host-based firewall rule set

*./jewelRunner.py -f /path/to/ipfilter.log -io ipfilter -target 10.10.10.1 -filter 10.10.10.2*

Parse ipSec log for target IP 10.10.10.1 and create host-based firewall rule set

*./jewelRunner.py -f /path/to/ipsec.log -io ipsec -target 10.10.10.1*

Parse ipSec log for target IP 10.10.10.1, isolate entries for 10.10.10.2 and create host-based firewall rule set

*./jewelRunner.py -f /path/to/ipsec.log -io ipsec -target 10.10.10.1 -filter 10.10.10.2*

## Assumptions and Caveats

* I have tried to include references wherever I borrowed from others. If I have missed someone, it was unintentional, lest I incur the wrath of the squirrel man.
* In retrospect I should have done this in Bro-Script. This is on my list. I'd also like to try using scapy to create and deploy the rules in real time as packets are read.
* This code is in-efficient. Several functions are repeated in each module. Future work includes plans for the creation of a utility module to consolidate these functions.
* The higher port is always assumed to be the initiator of the connection. This may not always be the case.
* JewelRunner will not create rules for high-port (>50000) to high-port traffic. However, it will report these flows in the output.
* JewelRunner will not create rules for low-port (< 1023) to low-port traffic. However, it will report these flows in the output.
* When an filter IP is specified, jewelRunner makes no assumptions about the source port (ie. > 1023) when creating the host-based firewall rules. Rules will be created using the source port specified in the log file. It is up to the user to generalize these rules later on.  
* JewelRunner assumes that any traffic it sees is allowed. Any rules should be ultimately adjudicated by the application and product teams.
* JewelRunner is intended to support "proof-of-concept" activities for micro-segmentation. There are several Enterprise tools that will do this far more effectively at the enterprise level (12 ,13)

## Future Work

1. Add support for iptables
2. Give user the choice to create specific flavor of firewall rules using pcap contents
3. Filter out passive ftp traffic
4. Parse ipv6
5. Handle broadcast traffic
6. Add option for file output
7. Add feature that will make recommendations to consolidate rules from single IPs to VLANs
8. Add ephemeral cmd line switch to clean up ports
9. Remove redundancies. Create module for utility functions.

## Thanks

Adopted from original scripts created by:
* brifordwylie @ https://github.com/brifordwylie
* RemiDesgrange @ https://github.com/RemiDesgrange
* saylenty @ https://github.com/saylenty                                              
