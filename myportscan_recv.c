//
//  myportscan_recv.c
//
//
//  Created by Sit King Lok on H26/03/17.
//
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "spoofit.h"

#define INTERFACE "eth1"
#define INTERFACE_PREFIX 14

char SOURCE[100],DEST[100];
int DEST_P,SOURCE_P_START,SOURCE_P_END;

struct sp_wait_packet pinfo;

int main(int argc, char *argv[])
{
    int fd, this_port;
    
    if (argc != 6) {
        fprintf(stderr, "usage: %s <myIP> <destIP> <myPort> <startPort> <endPort>\n", argv[0]);
		exit(1);
    }
    
    /* preparing some work */
    DEV_PREFIX = INTERFACE_PREFIX;
    strcpy(DEST,argv[1]);
    strcpy(SOURCE,argv[2]);
    DEST_P=atoi(argv[3]);
    SOURCE_P_START=atoi(argv[4]);
    SOURCE_P_END=atoi(argv[5]);
    
    fd = open_receiving(INTERFACE, IO_NONBLOCK); /* nonblocking IO */
    
    while (1) {
        this_port = wait_packet(fd,&pinfo,SOURCE,SOURCE_P_START,SOURCE_P_END, DEST, DEST_P,0);
        if (pinfo.flags == (SYN|ACK)) {
            printf("Port %d is open\n", this_port);
        } else if (pinfo.flags == (ACK|RST) || pinfo.flags == RST) {
            printf("Port %d is closed\n", this_port);
        }
    }
    
    close_receiving();
    
    return 0;
}