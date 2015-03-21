/*
 * tcp_pkt.h
 * 
 * routines for creating TCP packets, and sending them into sockets.
 *
 * (version 0.3)
 *
 * 
 * BUGFIX: - it seems like the TCP pseudo header checksum was
 *           acting up in serveral cases.
 * ADDED : - HEXDUMP macro. 
 *         - packet dump handling
 *
 ******
 * - Oct 25, 2010
 *    - Fix the variable alignment issue in differnet platforms (Patrick)
 *
 * - Adapted from TCP port stealth scanning
 *   http://www.phrack.org/issues.html?issue=49&id=15
 * - Modified by Patrick P. C. Lee for CSCI5470 assignment 2.
 */

/* remove inlines for smaller size but lower speed */

#ifndef __tcp_pkt_h__
#define __tcp_pkt_h__

#include <netinet/in.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#define IPHDRSIZE  20
#define TCPHDRSIZE  20
#define PSEUDOHDRSIZE  12

/* ********** RIPPED CODE START ******************************** */

/*
 * in_cksum --
 *  Checksum routine for Internet Protocol family headers (C Version)
 */
unsigned short in_cksum(addr, len)
	u_short *addr;
	int len;
{
	register int nleft = len;
	register u_short *w = addr;
	register int sum = 0;
	u_short answer = 0;

	/*
	 * Our algorithm is simple, using a 32 bit accumulator (sum), we add
	 * sequential 16 bit words to it, and at the end, fold back all the
	 * carry bits from the top 16 bits into the lower 16 bits.
	 */
	while (nleft > 1)  {
		sum += *w++;
		nleft -= 2;
	}

	/* mop up an odd byte, if necessary */
	if (nleft == 1) {
		*(u_char *)(&answer) = *(u_char *)w ;
		sum += answer;
	}

	/* add back carry outs from top 16 bits to low 16 bits */
	sum = (sum >> 16) + (sum & 0xffff);   /* add hi 16 to low 16 */
	sum += (sum >> 16);                   /* add carry */
	answer = ~sum;                        /* truncate to 16 bits */
	return(answer);
}

/* ********** RIPPED CODE END ******************************** */

/*
 * HEXDUMP()
 * 
 * not too much to explain
 */
inline void HEXDUMP(unsigned len, unsigned char *data) 
{ 
	unsigned i;
	for (i=0;i<len;i++) printf("%02X%c",*(data+i),((i+1)%16) ? ' ' : '\n');
}

/*
 * tcpip_send()
 * 
 * sends a totally customized datagram with TCP/IP headers. 
 */

inline int tcpip_send(int      socket,
		struct sockaddr_in *address,
		unsigned int s_addr,
		unsigned int t_addr,
		unsigned      s_port,
		unsigned      t_port,
		unsigned char tcpflags,
		unsigned int seq,
		unsigned int ack,
		unsigned      win,
		char          *datagram,
		unsigned      datasize)
{

	struct pseudohdr  {
		unsigned int saddr;
		unsigned int daddr;
		char useless;
		unsigned char protocol;
		unsigned short tcplength;
	} __attribute__ ((packed));

	unsigned char packet[2048];
	struct iphdr        *ip     = (struct iphdr *)packet;
	struct tcphdr       *tcp    = (struct tcphdr *)(packet+IPHDRSIZE);
	struct pseudohdr    *pseudo = (struct pseudohdr *)(packet+IPHDRSIZE-PSEUDOHDRSIZE);
	unsigned char       *data   = (unsigned char *)(packet+IPHDRSIZE+TCPHDRSIZE);      

	/*
	 * The above casts will save us a lot of memcpy's later.
	 * The pseudo-header makes this way become easier than a union.
	 */

	memcpy(data,datagram,datasize);
	memset(packet,0,TCPHDRSIZE+IPHDRSIZE);

	/* The data is in place, all headers are zeroed. */

	pseudo->saddr = s_addr;
	pseudo->daddr = t_addr;
	pseudo->protocol = IPPROTO_TCP;   
	pseudo->tcplength = htons(TCPHDRSIZE+datasize);  

	/* The TCP pseudo-header was created. */

	tcp->source = htons(s_port);
	tcp->dest = htons(t_port);
	tcp->doff = 5;          /* 20 bytes, (no options) */
	tcp->fin = 0;
	tcp->syn = 1;
	tcp->rst = 0;
	tcp->psh = 0;
	tcp->ack = 0;
	tcp->urg = 0;
	tcp->res2 = 0;
	tcp->seq = htonl(seq);
	tcp->ack_seq = htonl(ack);
	tcp->window = htons(win); /* we don't need any bigger, I guess. */

	/* The necessary TCP header fields are set. */

	tcp->check = in_cksum(pseudo,PSEUDOHDRSIZE+TCPHDRSIZE+datasize);

	memset(packet,0,IPHDRSIZE); 
	/* The pseudo-header is wiped to clear the IP header fields */

	ip->saddr    = s_addr;
	ip->daddr    = t_addr;
	ip->version  = 4;
	ip->ihl      = 5;
	ip->ttl      = 64;
	ip->id       = random()%1996;
	ip->protocol = IPPROTO_TCP; /* should be 6 */
	ip->tot_len  = htons(IPHDRSIZE + TCPHDRSIZE + datasize);
	ip->check    = in_cksum((char *)packet,IPHDRSIZE);

	/* The IP header is intact. The packet is ready. */

#ifdef TCP_PKT_DEBUG
	printf("Packet ready. Dump: \n");
#ifdef TCP_PKT_DEBUG_DATA
	HEXDUMP(IPHDRSIZE+TCPHDRSIZE+datasize,packet);
#else
	HEXDUMP(IPHDRSIZE+TCPHDRSIZE,packet);
#endif
	printf("\n");
#endif

	return sendto(socket, packet, IPHDRSIZE+TCPHDRSIZE+datasize, 0, 
				(struct sockaddr *)address, sizeof(struct sockaddr)); 
	
	/* And off into the raw socket it goes. */
}

#endif
