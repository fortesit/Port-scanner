# Port-scanner
To scan a range of ports is opened or not
./myportscan_send <myIP> <scannedIP> <srcPort> <startPort> <endPort>,
where myIP is my own IP address, scannedIP is the IP address of the scanned destination host, srcPort is the source port that the port scanner will use to construct the scanned packets, and the port scanner will scan all the ports between startPort and endPort (inclusively). For example,
./myportscan_send 192.168.77.1 192.168.77.2 49049 20 25
It means that the port scanner is hosted on 192.168.77.1, the port scanner will scan the ports 20 to 25 of 192.168.77.2, and the source ports of the TCP SYN packets will be 49049.The program myportscan recv will monitor the reply packets from the scanned ports. It takes the following inputs:
./myportscan_recv <myIP> <scannedIP> <srcPort> <startPort> <endPort>.To be documented…