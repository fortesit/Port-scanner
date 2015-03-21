
/*---=[ spoofit.h ]=------------------------------------------------------*/
/**************************************************************************/
/* Spoofit.h - Include file for easy creating of spoofed TCP packets      */
/*             Requires LINUX 1.3.x (or later) Kernel                     */
/*             (illustration for 'A short overview of IP spoofing')       */
/*             V.1 - Copyright 1996 - Brecht Claerhout                    */
/*                                                                        */
/*  Purpose - Providing skilled people with a easy to use spoofing source */
/*            I used it to be able to write my tools fast and short.      */
/*            Mind you this is only illustrative and can be easily        */
/*            optimised.                                                  */
/*                                                                        */
/*  Author - Brecht Claerhout <Coder@reptile.rug.ac.be>                   */
/*           Serious advice, comments, statements, greets, always welcome */
/*           flames, moronic 3l33t >/dev/null                             */
/*                                                                        */
/*  Disclaimer - This file is for educational purposes only. I am in      */
/*               NO way responsible for what you do with this file,       */
/*               or any damage you or this file causes.                   */
/*                                                                        */
/*  For whom - People with a little knowledge of TCP/IP, C source code    */
/*             and general UNIX. Otherwise, please keep your hands of,    */
/*             and catch up on those things first.                        */
/*                                                                        */
/*  Limited to - Linux 1.3.X or higher.                                   */
/*               If you know a little about your OS, shouldn't be to hard */
/*               to port.                                                 */
/*                                                                        */
/* Important note - You might have noticed I use non standard packet      */
/*                  header struct's. How come?? Because I started like    */
/*                  that on Sniffit because I wanted to do the            */
/*                  bittransforms myself.                                 */
/*                  Well I got so damned used to them, I keep using them, */
/*                  they are not very different, and not hard to use, so  */
/*                  you'll easily use my struct's without any problem,    */
/*                  this code and the examples show how to use them.      */
/*                  my apologies for this inconvenience.                  */
/*                                                                        */
/* None of this code can be used in commercial software. You are free to  */
/* use it in any other non-commercial software (modified or not) as long  */
/* as you give me the credits for it. You can spread this include file,   */
/* but keep it unmodified.                                                */
/*                                                                        */
/**************************************************************************/
/*                                                                        */
/* Easiest way to understand this library is to look at the use of it, in */
/* the example progs.                                                     */
/*                                                                        */
/**** Sending packets *****************************************************/
/*                                                                        */
/* int open_sending (void)                                                */
/*   Returns a filedescriptor to the sending socket.                      */
/*   close it with close (int filedesc)                                   */
/*                                                                        */
/* void transmit_TCP (int sp_fd, char *sp_data,                           */
/*	              int sp_ipoptlen, int sp_tcpoptlen, int sp_datalen,  */
/*                    char *sp_source, unsigned short sp_source_port,     */
/*                    char *sp_dest,unsigned short sp_dest_port,          */
/*                    unsigned long sp_seq, unsigned long sp_ack,         */
/*                    unsigned short sp_flags)                            */
/*   fire data away in a TCP packet                                       */
/*    sp_fd         : raw socket filedesc.                                */
/*    sp_data       : IP options (you should do the padding)              */
/*                    TCP options (you should do the padding)             */
/*                    data to be transmitted                              */
/*                    (NULL is nothing)                                   */
/*                    note that all is optional, and IP en TCP options are*/
/*                    not often used.                                     */
/*                    All data is put after eachother in one buffer.      */
/*    sp_ipoptlen   : length of IP options (in bytes)                     */
/*    sp_tcpoptlen  : length of TCP options (in bytes)                    */
/*    sp_datalen    : amount of data to be transmitted (bytes)            */
/*    sp_source     : spoofed host that"sends packet"                     */
/*    sp_source_port: spoofed port that "sends packet"                    */
/*    sp_dest       : host that should receive packet                     */
/*    sp_dest_port  : port that should receive packet                     */
/*    sp_seq        : sequence number of packet                           */
/*    sp_ack        : ACK of packet                                       */
/*    sp_flags      : flags of packet (URG,ACK,PSH,RST,SYN,FIN)           */
/*                                                                        */
/* void transmit_UDP (int sp_fd, char *sp_data,                           */
/*                    int sp_ipoptlen, int sp_datalen,                    */
/*		      char *sp_source, unsigned short sp_source_port,     */
/*                    char *sp_dest, unsigned short sp_dest_port)         */
/*   fire data away in an UDP packet                                      */
/*    sp_fd         : raw socket filedesc.                                */
/*    sp_data       : IP options                                          */
/*                    data to be transmitted                              */
/*                    (NULL if none)                                      */
/*    sp_ipoptlen   : length of IP options (in bytes)                     */
/*    sp_datalen    : amount of data to be transmitted                    */
/*    sp_source     : spoofed host that"sends packet"                     */
/*    sp_source_port: spoofed port that "sends packet"                    */
/*    sp_dest       : host that should receive packet                     */
/*    sp_dest_port  : port that should receive packet                     */
/*                                                                        */
/**** Receiving packets ***************************************************/
/*                                                                        */
/* int open_receiving (char *rc_device, char mode)                        */
/*   Returns fdesc to a receiving socket                                  */
/*        (if mode: IO_HANDLE don't call this twice, global var           */
/*         rc_fd_abc123 is  initialised)                                  */
/*     rc_device: the device to use e.g. "eth0", "ppp0"                   */
/*                be sure to change DEV_PREFIX accordingly!               */
/*                DEV_PREFIX is the length in bytes of the header that    */
/*                comes with a SOCKET_PACKET due to the network device    */
/*     mode: 0: normal mode, blocking, (read will wait till packet        */
/*           comes, mind you, we are in PROMISC mode)                     */
/*           IO_NONBLOCK: non-blocking mode (read will not wait till      */
/*           usefull for active polling)                                  */
/*           IO_HANDLE installs the signal handler that updates SEQ,ACK,..*/
/*           (IO_HANDLE is not recommended to use, as it should be        */
/*           modified according to own use, and it works bad on heavy     */
/*           traffic continuous monitoring. I needed it once, but left it */
/*           in to make you able to have a look at Signal handled IO,     */
/*           personally I would have removed it, but some thought it      */
/*           doesn't do any harm anyway, so why remove... )               */
/*           (I'm not giving any more info on IO_HANDLE as it is not      */
/*           needed for the example programs, and interested people can   */
/*           easilythey figure the code out theirselves.)                 */
/*           (Besides IO_HANDLE can only be called ONCE in a program,     */
/*           other modes multiple times)                                  */
/*                                                                        */
/* int get_packet (int rc_fd, char *buffer, int *TCP_UDP_start,           */
/*         	   unsigned char *proto)                                  */
/*        This waits for a packet (mode default) and puts it in buffer or */
/*        returns whether there is a pack or not (IO_NONBLOCK).           */
/*        It returns the packet length if there is one available, else 0  */
/*                                                                        */
/* int wait_packet(int wp_fd,struct sp_wait_packet *ret_values,           */
/*                  char *wp_source, unsigned short wp_source_port,       */
/*                  char *wp_dest, unsigned short wp_dest_port,           */
/*	            int wp_flags, int wait_time);                         */
/*   wp_fd: a receiving socket (default or IO_NONBLOCK)                   */
/*   ret_values: pointer to a sp_wait_packet struct, that contains SEQ,   */
/*               ACK, flags, datalen of that packet. For further packet   */
/*               handling see the examples.                               */
/*                  struct sp_wait_packet  {                              */
/*                   	unsigned long seq,ack;                            */
/*                      unsigned short flags;                             */
/*                      int datalen;                                      */
/*                      };                                                */
/*   wp_source, wp_source_port : sender of packet                         */
/*   wp_dest, wp_dest_port     : receiver of packet                       */
/*   wp_flags: flags that should be present in packet.. (mind you there   */
/*             could be more present, so check on return)                 */
/*             note: if you don't care about flag, use 0                  */
/*   wait_time: if not zero, this function will return -1 if no correct   */
/*              packet has arrived within wait_time secs.                 */
/*              (only works on IO_NONBLOCK socket)                        */
/*                                                                        */
/* void set_filter (char *f_source, unsigned short f_source_port,         */
/*                  char *f_dest, unsigned short f_dest_port)             */
/*        (for use with IO_HANDLE)                                        */
/*        Start the program to watch all trafic from source/port to       */
/*        dest/port. This enables the updating of global data. Can        */
/*        be called multiple times.                                       */
/*                                                                        */
/* void close_receiving (void)                                            */
/*           When opened a IO_HANDLE mode receiving socket close it with  */
/*           this.                                                        */
/*                                                                        */
/**** Global DATA (IO_HANDLE mode) ****************************************/
/*                                                                        */
/* When accessing global data, copy the values to local vars and then use */
/* them. Reduce access time to a minimum.                                 */
/* Mind you use of this is very limited, if you are a novice on IO, just  */
/* ignore it, the other functions are good enough!). If not, rewrite the  */
/* handler for your own use...                                            */
/*                                                                        */
/* sig_atomic_t SP_DATA_BUSY                                              */
/*        Put this on NON-ZERO when accesing global data. Incoming        */
/*        packets will be ignored then, data can not be overwritten.      */
/*                                                                        */
/* unsigned long int CUR_SEQ, CUR_ACK;                                    */
/*        Last recorded SEQ and ACK number of the filtered "stream".      */
/*        Before accessing this data set SP_DATA_BUSY non-zero,           */
/*        afterward set it back to zero.                                  */
/*                                                                        */
/* unsigned long int CUR_COUNT;                                           */
/*        increased everytime other data is updated                       */
/*                                                                        */
/* unsigned int CUR_DATALEN;                                              */
/*	  Length of date in last TCP packet			          */
/*                                                                        */
/**************************************************************************/

#include "sys/socket.h"       /* includes, what would we do without them  */
#include "netdb.h"
#include "stdlib.h"
#include "unistd.h"
#include "stdio.h"
#include "errno.h"
#include "netinet/in.h"
#include "netinet/ip.h"
#include "linux/if.h"
#include "sys/ioctl.h"
#include "sys/types.h"
#include "signal.h"
#include "fcntl.h"

#undef  DEBUG
#define IP_VERSION 	4                 /* keep y'r hands off...         */
#define MTU 		1500
#define IP_HEAD_BASE 	20                /* using fixed lengths to send   */
#define TCP_HEAD_BASE 	20                /* no options etc...             */
#define UDP_HEAD_BASE 	8                 /* Always fixed                  */

#define IO_HANDLE	1
#define IO_NONBLOCK	2

int DEV_PREFIX = 9999;
sig_atomic_t WAIT_PACKET_WAIT_TIME=0;

/**** IO_HANDLE ************************************************************/
int rc_fd_abc123;
sig_atomic_t RC_FILTSET=0;
char rc_filter_string[50];                       /* x.x.x.x.p-y.y.y.y.g  */

sig_atomic_t SP_DATA_BUSY=0;
unsigned long int CUR_SEQ=0, CUR_ACK=0, CUR_COUNT=0;
unsigned int CUR_DATALEN;
unsigned short CUR_FLAGS;
/***************************************************************************/

struct sp_wait_packet
{
	unsigned long seq,ack;
	unsigned short flags;
	int datalen;
};

/* Code from Sniffit - BTW my own program.... no copyright violation here */
#define URG 32       /* TCP flags */
#define ACK 16
#define PSH 8
#define RST 4
#define SYN 2
#define FIN 1

struct PACKET_info
{
	int len, datalen;
	unsigned long int seq_nr, ACK_nr;
	u_char FLAGS;
};

struct IP_header                        /* The IPheader (without options) */
{
    unsigned char verlen, type;
    unsigned short length, ID, flag_offset;
    unsigned char TTL, protocol;
    unsigned short checksum;
    unsigned long int source, destination;
};

struct TCP_header                     /* The TCP header (without options) */
{
    unsigned short source, destination;
    unsigned long int seq_nr, ACK_nr;
    unsigned short offset_flag, window, checksum, urgent;
};

struct UDP_header                                      /* The UDP header */
{
    unsigned short source, destination;
    unsigned short length, checksum;
};

struct pseudo_IP_header          /* The pseudo IP header (checksum calc) */
{
    unsigned long int source, destination;
	char zero_byte, protocol;
	unsigned short TCP_UDP_len;
};

/* data structure for argument passing  */

struct sp_data_exchange	{
	int fd;                                /* Sh!t from transmit_TCP  */
	char *data;
	int datalen;
	char *source; unsigned short source_port;
	char *dest;   unsigned short dest_port;
    unsigned long seq, ack;
    unsigned short flags;
    
	char *buffer;               /* work buffer */
    
    int IP_optlen;		   /* IP options length in bytes  */
    int TCP_optlen;		   /* TCP options length in bytes */
};

/**************** all functions  *******************************************/
void transmit_TCP (int fd, char *sp_data,
		     	   int sp_ipoptlen, int sp_tcpoptlen, int sp_datalen,
		           char *sp_source, unsigned short sp_source_port,
                   char *sp_dest, unsigned short sp_dest_port,
                   unsigned long sp_seq, unsigned long sp_ack,
                   unsigned short sp_flags);

void transmit_UDP (int sp_fd, char *sp_data,
                   int  ipoptlen, int sp_datalen,
		           char *sp_source, unsigned short sp_source_port,
                   char *sp_dest, unsigned short sp_dest_port);

int get_packet (int rc_fd, char *buffer, int *, unsigned char*);
int wait_packet(int wp_fd,struct sp_wait_packet *ret_values,
                char *wp_source, unsigned short wp_source_port_start, unsigned short wp_source_port_end,
                char *wp_dest, unsigned short wp_dest_port,
                int wait_time) ;



static unsigned long sp_getaddrbyname(char *);

int open_sending (void);
int open_receiving (char *, char);
void close_receiving (void);

void sp_send_packet (struct sp_data_exchange *, unsigned char);
void sp_fix_TCP_packet (struct sp_data_exchange *);
void sp_fix_UDP_packet (struct sp_data_exchange *);
void sp_fix_IP_packet (struct sp_data_exchange *, unsigned char);
unsigned short in_cksum(unsigned short *, int );

void rc_sigio (int);
void set_filter (char *, unsigned short, char *, unsigned short);

/********************* let the games commence ****************************/

static unsigned long sp_getaddrbyname(char *sp_name)
{
    struct hostent *sp_he;
    int i;
    
    if(isdigit(*sp_name))
        return inet_addr(sp_name);
    
    for(i=0;i<100;i++)
    {
        if(!(sp_he = gethostbyname(sp_name)))
        {printf("WARNING: gethostbyname failure!\n");
            sleep(1);
            if(i>=3)       /* always a retry here in this kind of application */
                printf("Coudn't resolv hostname."), exit(1);
        }
        else break;
    }
    return sp_he ? *(long*)*sp_he->h_addr_list : 0;
}

int open_sending (void)
{
    struct protoent *sp_proto;
    int sp_fd;
    int dummy=1;
    
    /* they don't come rawer */
    if ((sp_fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW))==-1)
        perror("Couldn't open Socket."), exit(1);
    
#ifdef DEBUG
	printf("Raw socket ready\n");
#endif
    return sp_fd;
}

void sp_send_packet (struct sp_data_exchange *sp, unsigned char proto)
{
    int sp_status;
    struct sockaddr_in sp_server;
    struct hostent *sp_help;
    int HEAD_BASE;
    
    /* Construction of destination */
    bzero((char *)&sp_server, sizeof(struct sockaddr));
    sp_server.sin_family = AF_INET;
    sp_server.sin_addr.s_addr = inet_addr(sp->dest);
    if (sp_server.sin_addr.s_addr == (unsigned int)-1)
    {                      /* if target not in DOT/number notation */
        if (!(sp_help=gethostbyname(sp->dest)))
            fprintf(stderr,"unknown host %s\n", sp->dest), exit(1);
        bcopy(sp_help->h_addr, (caddr_t)&sp_server.sin_addr, sp_help->h_length);
    };
    
    switch(proto)
   	{
        case 6: HEAD_BASE = TCP_HEAD_BASE;  break;                  /* TCP */
        case 17: HEAD_BASE = UDP_HEAD_BASE; break;                  /* UDP */
        default: exit(1); break;
	};
    sp_status = sendto(sp->fd, (char *)(sp->buffer), sp->datalen+HEAD_BASE+IP_HEAD_BASE+sp->IP_optlen, 0,
                       (struct sockaddr *)&sp_server,sizeof(struct sockaddr));
    if (sp_status < 0 || sp_status != sp->datalen+HEAD_BASE+IP_HEAD_BASE+sp->IP_optlen)
    {
        if (sp_status < 0)
            perror("Sendto"), exit(1);
        printf("hmm... Only transmitted %d of %d bytes.\n", sp_status,
               sp->datalen+HEAD_BASE);
    };
#ifdef DEBUG
	printf("Packet transmitted...\n");
#endif
}

void sp_fix_IP_packet (struct sp_data_exchange *sp, unsigned char proto)
{
    struct IP_header *sp_help_ip;
    int HEAD_BASE;
    
    switch(proto)
   	{
        case 6: HEAD_BASE = TCP_HEAD_BASE;  break;                  /* TCP */
        case 17: HEAD_BASE = UDP_HEAD_BASE; break;                  /* UDP */
        default: exit(1); break;
	};
    
    sp_help_ip = (struct IP_header *) (sp->buffer);
    sp_help_ip->verlen = (IP_VERSION << 4) | ((IP_HEAD_BASE+sp->IP_optlen)/4);
    sp_help_ip->type = 0;
    sp_help_ip->length = htons(IP_HEAD_BASE+HEAD_BASE+sp->datalen+sp->IP_optlen+sp->TCP_optlen);
    sp_help_ip->ID = htons(12545);                                  /* TEST */
    sp_help_ip->flag_offset = 0;
    sp_help_ip->TTL = 69;
    sp_help_ip->protocol = proto;
    sp_help_ip->source = sp_getaddrbyname(sp->source);
    sp_help_ip->destination =  sp_getaddrbyname(sp->dest);
    sp_help_ip->checksum=in_cksum((unsigned short *) (sp->buffer),
                                  IP_HEAD_BASE+sp->IP_optlen);
#ifdef DEBUG
	printf("IP header fixed...\n");
#endif
}

void sp_fix_TCP_packet (struct sp_data_exchange *sp)
{
    char sp_pseudo_ip_construct[MTU];
    struct TCP_header *sp_help_tcp;
    struct pseudo_IP_header *sp_help_pseudo;
    int i;
    
    for(i=0;i<MTU;i++)
    {sp_pseudo_ip_construct[i]=0;}
    
    sp_help_tcp = (struct TCP_header *) (sp->buffer+IP_HEAD_BASE+sp->IP_optlen);
    sp_help_pseudo = (struct pseudo_IP_header *) sp_pseudo_ip_construct;
    
    sp_help_tcp->offset_flag = htons( (((TCP_HEAD_BASE+sp->TCP_optlen)/4)<<12) | sp->flags);
    sp_help_tcp->seq_nr = htonl(sp->seq);
    sp_help_tcp->ACK_nr = htonl(sp->ack);
    sp_help_tcp->source = htons(sp->source_port);
    sp_help_tcp->destination = htons(sp->dest_port);
    sp_help_tcp->window = htons(0x7c00);             /* dummy for now 'wujx' */
    
    sp_help_pseudo->source = sp_getaddrbyname(sp->source);
    sp_help_pseudo->destination =  sp_getaddrbyname(sp->dest);
    sp_help_pseudo->zero_byte = 0;
    sp_help_pseudo->protocol = 6;
    sp_help_pseudo->TCP_UDP_len = htons(sp->datalen+TCP_HEAD_BASE+sp->TCP_optlen);
    
    memcpy(sp_pseudo_ip_construct+12, sp_help_tcp, sp->TCP_optlen+sp->datalen+TCP_HEAD_BASE);
    sp_help_tcp->checksum=in_cksum((unsigned short *) sp_pseudo_ip_construct,
                                   sp->datalen+12+TCP_HEAD_BASE+sp->TCP_optlen);
#ifdef DEBUG
	printf("TCP header fixed...\n");
#endif
}

void transmit_TCP (int sp_fd, char *sp_data,
                   int sp_ipoptlen, int sp_tcpoptlen, int sp_datalen,
		           char *sp_source, unsigned short sp_source_port,
                   char *sp_dest, unsigned short sp_dest_port,
                   unsigned long sp_seq, unsigned long sp_ack,
                   unsigned short sp_flags)
{
    char sp_buffer[1500];
    struct sp_data_exchange sp_struct;
    
    bzero(sp_buffer,1500);
    if (sp_ipoptlen!=0)
        memcpy(sp_buffer+IP_HEAD_BASE,sp_data,sp_ipoptlen);
    
    if (sp_tcpoptlen!=0)
        memcpy(sp_buffer+IP_HEAD_BASE+TCP_HEAD_BASE+sp_ipoptlen,
               sp_data+sp_ipoptlen,sp_tcpoptlen);
    if (sp_datalen!=0)
        memcpy(sp_buffer+IP_HEAD_BASE+TCP_HEAD_BASE+sp_ipoptlen+sp_tcpoptlen,
               sp_data+sp_ipoptlen+sp_tcpoptlen,sp_datalen);
    
    sp_struct.fd          = sp_fd;
    sp_struct.data        = sp_data;
    sp_struct.datalen     = sp_datalen;
    sp_struct.source      = sp_source;
    sp_struct.source_port = sp_source_port;
    sp_struct.dest        = sp_dest;
    sp_struct.dest_port   = sp_dest_port;
    sp_struct.seq         = sp_seq;
    sp_struct.ack         = sp_ack;
    sp_struct.flags       = sp_flags;
    sp_struct.buffer      = sp_buffer;
    sp_struct.IP_optlen   = sp_ipoptlen;
    sp_struct.TCP_optlen  = sp_tcpoptlen;
    
    sp_fix_TCP_packet(&sp_struct);
    sp_fix_IP_packet(&sp_struct, 6);
    sp_send_packet(&sp_struct, 6);
}

void sp_fix_UDP_packet (struct sp_data_exchange *sp)
{
    char sp_pseudo_ip_construct[MTU];
    struct UDP_header *sp_help_udp;
    struct pseudo_IP_header *sp_help_pseudo;
    int i;
    
    for(i=0;i<MTU;i++)
    {sp_pseudo_ip_construct[i]=0;}
    
    sp_help_udp = (struct UDP_header *) (sp->buffer+IP_HEAD_BASE+sp->IP_optlen);
    sp_help_pseudo = (struct pseudo_IP_header *) sp_pseudo_ip_construct;
    
    sp_help_udp->source = htons(sp->source_port);
    sp_help_udp->destination = htons(sp->dest_port);
    sp_help_udp->length =  htons(sp->datalen+UDP_HEAD_BASE);
    
    sp_help_pseudo->source = sp_getaddrbyname(sp->source);
    sp_help_pseudo->destination =  sp_getaddrbyname(sp->dest);
    sp_help_pseudo->zero_byte = 0;
    sp_help_pseudo->protocol = 17;
    sp_help_pseudo->TCP_UDP_len = htons(sp->datalen+UDP_HEAD_BASE);
    
    memcpy(sp_pseudo_ip_construct+12, sp_help_udp, sp->datalen+UDP_HEAD_BASE);
    sp_help_udp->checksum=in_cksum((unsigned short *) sp_pseudo_ip_construct,
                                   sp->datalen+12+UDP_HEAD_BASE);
#ifdef DEBUG
	printf("UDP header fixed...\n");
#endif
}

void transmit_UDP (int sp_fd, char *sp_data,
                   int sp_ipoptlen, int sp_datalen,
		           char *sp_source, unsigned short sp_source_port,
                   char *sp_dest, unsigned short sp_dest_port)
{
    char sp_buffer[1500];
    struct sp_data_exchange sp_struct;
    
    bzero(sp_buffer,1500);
    
    if (sp_ipoptlen!=0)
        memcpy(sp_buffer+IP_HEAD_BASE,sp_data,sp_ipoptlen);
    if (sp_data!=NULL)
        memcpy(sp_buffer+IP_HEAD_BASE+UDP_HEAD_BASE+sp_ipoptlen,
               sp_data+sp_ipoptlen,sp_datalen);
    sp_struct.fd          = sp_fd;
    sp_struct.data        = sp_data;
    sp_struct.datalen     = sp_datalen;
    sp_struct.source      = sp_source;
    sp_struct.source_port = sp_source_port;
    sp_struct.dest        = sp_dest;
    sp_struct.dest_port   = sp_dest_port;
    sp_struct.buffer      = sp_buffer;
    sp_struct.IP_optlen   = sp_ipoptlen;
    sp_struct.TCP_optlen  = 0;
    
    sp_fix_UDP_packet(&sp_struct);
    sp_fix_IP_packet(&sp_struct, 17);
    sp_send_packet(&sp_struct, 17);
}

/* This routine stolen from ping.c -- HAHAHA!*/
unsigned short in_cksum(unsigned short *addr,int len)
{
    register int nleft = len;
    register unsigned short *w = addr;
    register int sum = 0;
    unsigned short answer = 0;
    
    while (nleft > 1)
    {
        sum += *w++;
        nleft -= 2;
    }
    if (nleft == 1)
    {
        *(u_char *)(&answer) = *(u_char *)w ;
        sum += answer;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = ~sum;
    return(answer);
}

/************************* Receiving department  ****************************/

int open_receiving (char *rc_device, char mode)
{
    int or_fd;
    struct sigaction rc_sa;
    int fcntl_flag;
    struct ifreq ifinfo;
    char test;
    
    /* create snoop socket and set interface promisc */
    if ((or_fd = socket(AF_INET, SOCK_PACKET, htons(0x3)))==-1)
        perror("Couldn't open Socket."), exit(1);
    
    strcpy(ifinfo.ifr_ifrn.ifrn_name,rc_device);
    if(ioctl(or_fd,SIOCGIFFLAGS,&ifinfo)<0)
        perror("Couldn't get flags."), exit(1);
    ifinfo.ifr_ifru.ifru_flags |= IFF_PROMISC;
    if(ioctl(or_fd,SIOCSIFFLAGS,&ifinfo)<0)
        perror("Couldn't set flags. (PROMISC)"), exit(1);
    
    if(mode&IO_HANDLE)
	{		/* install handler */
        rc_sa.sa_handler=rc_sigio;        /* we don't use signal()        */
        sigemptyset(&rc_sa.sa_mask);      /* because the timing window is */
        rc_sa.sa_flags=0;                 /* too big...                   */
        sigaction(SIGIO,&rc_sa,NULL);
	}
    
    if(fcntl(or_fd,F_SETOWN,getpid())<0)
        perror("Couldn't set ownership"), exit(1);
    
    if(mode&IO_HANDLE)
	{
        if( (fcntl_flag=fcntl(or_fd,F_GETFL,0))<0)
            perror("Couldn't get FLAGS"), exit(1);
        if(fcntl(or_fd,F_SETFL,fcntl_flag|FASYNC|FNDELAY)<0)
            perror("Couldn't set FLAGS"), exit(1);
        rc_fd_abc123=or_fd;
	}
    else
	{
        if(mode&IO_NONBLOCK)
		{
            if( (fcntl_flag=fcntl(or_fd,F_GETFL,0))<0)
                perror("Couldn't get FLAGS"), exit(1);
            if(fcntl(or_fd,F_SETFL,fcntl_flag|FNDELAY)<0)
                perror("Couldn't set FLAGS"), exit(1);
		};
	};
    
#ifdef DEBUG
	printf("Reading socket ready\n");
#endif
    return or_fd;
}

/* returns 0 when no packet read!  */
int get_packet (int rc_fd, char *buffer, int *TCP_UDP_start,unsigned  char *proto)
{
    char help_buffer[MTU];
    int pack_len;
    struct IP_header *gp_IPhead;
    
    pack_len = read(rc_fd,help_buffer,1500);
    if(pack_len<0)
	{
        if(errno==EWOULDBLOCK)
		{pack_len=0;}
        else
		{perror("Read error:"); exit(1);}
	};
    if(pack_len>0)
	{
        pack_len -= DEV_PREFIX;
        memcpy(buffer,help_buffer+DEV_PREFIX,pack_len);
        gp_IPhead = (struct IP_header *) buffer;
        if(proto != NULL)
            *proto = gp_IPhead->protocol;
        if(TCP_UDP_start != NULL)
            *TCP_UDP_start = (gp_IPhead->verlen & 0xF) << 2;
	}
    return pack_len;
}

void wait_packet_timeout (int sig)
{
    alarm(0);
    WAIT_PACKET_WAIT_TIME=1;
}

int wait_packet(int wp_fd,struct sp_wait_packet *ret_values,
                char *wp_source, unsigned short wp_source_port_start, unsigned short wp_source_port_end,
                char *wp_dest, unsigned short wp_dest_port,
                int wait_time)
{
    char wp_buffer[1500];
    struct IP_header *wp_iphead;
    struct TCP_header *wp_tcphead;
    unsigned long wp_sourcel, wp_destl;
    int wp_tcpstart;
    char wp_proto;
    
    wp_sourcel=sp_getaddrbyname(wp_source);
    wp_destl=sp_getaddrbyname(wp_dest);
    
    WAIT_PACKET_WAIT_TIME=0;
    if(wait_time!=0)
	{
        signal(SIGALRM,wait_packet_timeout);
        alarm(wait_time);
	}
    
    while(1)
    {
        while(get_packet(wp_fd, wp_buffer, &wp_tcpstart, &wp_proto)<=0)
        {
            if (WAIT_PACKET_WAIT_TIME!=0)	{alarm(0); return -1;}
        };
        if(wp_proto == 6)
        {
            wp_iphead= (struct IP_header *) wp_buffer;
            wp_tcphead= (struct TCP_header *) (wp_buffer+wp_tcpstart);
            if( (wp_sourcel==wp_iphead->source)&&(wp_destl==wp_iphead->destination) )
            {
                if( (ntohs(wp_tcphead->source)>=wp_source_port_start) && (ntohs(wp_tcphead->source)<=wp_source_port_end) &&
                   (ntohs(wp_tcphead->destination)==wp_dest_port) )
                {
                    // if( (wp_flags==0) || (ntohs(wp_tcphead->offset_flag)&wp_flags) )
                    {
                        ret_values->seq=ntohl(wp_tcphead->seq_nr);
                        ret_values->ack=ntohl(wp_tcphead->ACK_nr);
                        ret_values->flags=ntohs(wp_tcphead->offset_flag)&
						(URG|ACK|PSH|FIN|RST|SYN);
                        ret_values->datalen = ntohs(wp_iphead->length) -
                        ((wp_iphead->verlen & 0xF) << 2) -
                        ((ntohs(wp_tcphead->offset_flag) & 0xF000) >> 10);
                        alarm(0);
                        return (int)ntohs(wp_tcphead->source); // return port
                    }
                }
            }
        }
    }
    /*impossible to get here.. but anyways*/
    alarm(0); return -1;
}


void close_receiving (void)
{
    close(rc_fd_abc123);
}

void rc_sigio (int sig)                     /* Packet handling routine */
{
    char rc_buffer[1500];
    char packet_id [50];
    unsigned char *rc_so, *rc_dest;
    struct IP_header *rc_IPhead;
    struct TCP_header *rc_TCPhead;
    int pack_len;
    
    if(RC_FILTSET==0) return;
    
    if(SP_DATA_BUSY!=0)              /* skip this packet */
        return;
    
    pack_len = read(rc_fd_abc123,rc_buffer,1500);
    rc_IPhead = (struct IP_header *) (rc_buffer + DEV_PREFIX);
    if(rc_IPhead->protocol!=6) return;                          /* if not TCP */
    rc_TCPhead = (struct TCP_header *) (rc_buffer + DEV_PREFIX + ((rc_IPhead->verlen & 0xF) << 2));
    
    rc_so   = (unsigned char *) &(rc_IPhead->source);
    rc_dest = (unsigned char *) &(rc_IPhead->destination);   
    sprintf(packet_id,"%u.%u.%u.%u.%u-%u.%u.%u.%u.%u",
            rc_so[0],rc_so[1],rc_so[2],rc_so[3],ntohs(rc_TCPhead->source),
            rc_dest[0],rc_dest[1],rc_dest[2],rc_dest[3],ntohs(rc_TCPhead->destination)); 
	
    if(strcmp(packet_id,rc_filter_string)==0)
	{ 
        SP_DATA_BUSY=1;
        CUR_SEQ = ntohl(rc_TCPhead->seq_nr);
        CUR_ACK = ntohl(rc_TCPhead->ACK_nr);
        CUR_FLAGS = ntohs(rc_TCPhead->offset_flag);
        CUR_DATALEN = ntohs(rc_IPhead->length) - 
        ((rc_IPhead->verlen & 0xF) << 2) -
        ((ntohs(rc_TCPhead->offset_flag) & 0xF000) >> 10);
        CUR_COUNT++;
        SP_DATA_BUSY=0;
	}
}

void set_filter (char *f_source, unsigned short f_source_port,
                 char *f_dest, unsigned short f_dest_port)
{
    unsigned char *f_so, *f_des;
    unsigned long f_sol, f_destl;
    
    RC_FILTSET=0;
    if(DEV_PREFIX==9999)
        fprintf(stderr,"DEV_PREFIX not set!\n"), exit(1);
    f_sol   = sp_getaddrbyname(f_source);
    f_destl = sp_getaddrbyname(f_dest);
    f_so    = (unsigned char *) &f_sol;
    f_des   = (unsigned char *) &f_destl;   
    sprintf(rc_filter_string,"%u.%u.%u.%u.%u-%u.%u.%u.%u.%u",
            f_so[0],f_so[1],f_so[2],f_so[3],f_source_port,	
            f_des[0],f_des[1],f_des[2],f_des[3],f_dest_port); 
    RC_FILTSET=1;
}


