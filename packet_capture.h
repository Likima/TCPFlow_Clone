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
#include <string.h>
#include <signal.h>
#include <time.h>
#include <ctype.h>
#include <sys/types.h>
#include <features.h>


void sigint_handler(int);
void packet_handler(u_char*, const struct pcap_pkthdr*, const u_char*);

typedef unsigned char u_char;

FILE* fp = NULL;

typedef struct{
    char** argv;
    char* fwname;
    int argc;
}cast_var;

typedef struct{
    char* time;
    char* payload;
    int len;
    const struct ip *ip_header;
    struct pcap_pkthdr *header;
}packetData;

#endif
