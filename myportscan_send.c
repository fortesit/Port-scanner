#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "tcp_pkt.h"

/*
 This is the program sending TCP SYN package doing port scan
 By Ken Lau
 */


int main(int argc, char *argv[])
{
    
	// argumnet number checking
	if(argc != 6)
	{
		fprintf(stderr, "usage: %s <myIP> <scannedIP> <srcPort> <startPort> <endPort>\n", argv[0]);
		exit(1);
	}
    
	unsigned int src_port = atoi(argv[3]), st_port = atoi(argv[4]), end_port = atoi(argv[5]);
	unsigned int i;
	int sd;
	struct sockaddr_in des_addr;
	/*
     Note:
     typedef uint32_t in_addr_t;
     struct in_addr {
     in_addr_t s_addr;
     };
     so we can direct use uint32_t instead
     */
	uint32_t src_ip, des_ip;
	
	srand(time(NULL));
	// doing IP conversion
	inet_aton(argv[1], (struct in_addr *)&src_ip);
	inet_aton(argv[2], (struct in_addr *)&des_ip);
    
	// seting socket
	perror("line");
	// need to use option: IPPROTO_TCP -> Indicates that the TCP protocol is to be used.
	// * IPPROTO_RAW -> Indicates that communications is to the IP layer
	// ref: http://www.phrack.org/issues.html?issue=49&id=15
	// ref: http://publib.boulder.ibm.com/infocenter/iseries/v5r3/index.jsp?topic=%2Fapis%2Fsocket.htm
	sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    
	memset(&des_addr, 0, sizeof(struct sockaddr));
	// choose AF_PACKET, not AF_INET, since we don't want to append any header
	des_addr.sin_family = AF_INET;
	// setting port to victim machine
	memcpy(&des_addr.sin_addr.s_addr, &des_ip, sizeof(des_ip));
    
	for(i = st_port; i <= end_port; i++)
	{
		// set the port where to go
		des_addr.sin_port = htons(i);
        
		fprintf(stdout, "Send packet to %u port\n", i);
		// tcpflags -> since not used to by the funciton, so set it 0
		// seq -> only a random number, ack -> 0, since 1st hand shake
		// window size -> just set it to be MTU size
		// since no data attached, so datagram set to NULL, datasize -> 0
		if(tcpip_send(sd, &des_addr, src_ip, des_ip, src_port, i, 0, rand()%1996, 0, 1500 , NULL, 0) < 0)
		{
			fprintf(stderr, "Error in sendign to port %d\n", i);
			perror("Filed in sendto()");
		}
	}
	
	close(sd);
	return 0;
}