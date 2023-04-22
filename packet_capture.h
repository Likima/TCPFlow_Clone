#ifndef PACKET_CAPTURE_H
#define PACKET_CAPTURE_H

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <net/ethernet.h> 
#include <errno.h>
#include <sys/socket.h>
#include <dirent.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <ctype.h>
#include <sys/types.h>
#include <features.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <unistd.h>
#include <sys/utsname.h>
#include <stdbool.h>
#include <zlib.h>
#include <unistd.h>

void sigint_handler(int);
void packet_handler(u_char*, const struct pcap_pkthdr*, const u_char*);
void sigint_handler(int);
void decode_udp(const struct udphdr*);
void decode_tcp(const struct tcphdr*);
void decode_ipvx(const struct ip*);
void tcpwritef(const struct tcphdr*);

#define BUFSIZE 100
typedef unsigned char u_char;

FILE* fp = NULL;
FILE* ipfp = NULL;
bool cprint = false;
bool html = false;

typedef struct{
    char* type;
    char* time;
    char* payload;
    int len;
    const struct ip *ip_header;
    const struct pcap_pkthdr *header;
}packetData;

#endif
