# nDPI and PcapPlusPlus
Develop a command line application to perform deep packet inspection over live traffic capture. 

## Description
The software must read packets from real ethernet device and inject that packet to nDPI library. Once nDPI
finish deep packet inspection for that connection, application need to save protocol, category and domain
for that connection.

1. Once packet comes try to generate unique connection id based on source IP & port, destination IP and port. Assign connection unique autoincrement identifier (uid) too.
2. Once connection id detected try to check if nDPI detection is pending or finished.
3. If nDPI detection is completed then do nothing and skip packet processing at all.
4. If nDPI detection is not started yet then you need to create new nDPI flow structure and save it inside connection tracking details
5. If nDPI detection is on-going then you need to use already created nDPI flow structure for that packet by retrieving from connection tracking details.
6. After each packet for that connection each packet should be injected into nDPI and get protocol detection status. If protocol already detected mark nDPI status for that connection as DONE. So future packets won’t be injected inside nDPI
7. If there are more than N (configurable) packets passed into nDPI then mark detection step as DONE by saying it is UNKNOWN protocol, category and empty domain.
8. Once protocol, category and domain is detected application should save it inside HashMap by using connection::uid as a key.
9. Once application stopped by

## Input
- Required parameters:
 -i: input network interface (it could be Linux assigned interface names eth0 or MAC address or PCI
address whatever you may feel easy/straight forward based on runtime capture engine)
- Optional parameters:
 --N: Max number of packets to send inside nDPI engine
## Output
The software must write the output on CLI screen following way.
- Connection Id, Protocol, Category, Domain
- 1, HTTP, Web, google.com
- 2, HTTPs, Web, plus.goolgle.com
- 3, DNS, Network, google.com
