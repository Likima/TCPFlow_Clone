#ifndef TCP_FUNCTIONS_H
#define TCP_FUNCTIONS_H
#include "packet_capture.h"

void sigint_handler(int sig) {
    printf("\nTerminating...\n");
    if(fp != NULL) fclose(fp);
    exit(0);
}

//void printInfo(const struct packetData pack, const u_char* packet, char src_ip[INET_ADDRSTRLEN], char dst_ip[INET_ADDRSTRLEN]){

//}
void decode_udp(const struct udphdr *packet){
    printf("   |   | Source: %hu\n", packet->source);
    printf("   |   | Destination: %hu\n", packet->dest);
    printf("   |   | Length: %hu\n", packet->len);
    printf("   |   | Check: %hu\n", packet->check);
}

void decode_tcp(const struct tcphdr *packet){
    printf("   |   | Source Port: %u\n", ntohs(packet->source));
    printf("   |   | Destination Port: %u\n", ntohs(packet->dest));
    printf("   |   | Sequence Number: %u\n", ntohl(packet->seq));
    printf("   |   | Acknowledgement Number: %u\n", ntohl(packet->ack_seq));
    printf("   |   | Data Offset: %d\n", packet->doff);
    
    printf("\nFLAGS\n\n   ____________________\n");
//                    |__________________|
    if(packet->syn == 1){
        printf("   |   SYN Flag Set   |\n");
    } else printf("   | SYN Flag NOT Set |\n");

    if(packet->rst == 1){
        printf("   |   RST Flag Set   |\n");
    } else printf("   | RST Flag NOT Set |\n");

    if(packet->psh == 1){
        printf("   |   PSH Flag Set   |\n");
    } else printf("   | PSH Flag NOT Set |\n");

    if(packet->ack == 1){
        printf("   |   ACK Flag Set   |\n");
    } else printf("   | ACK Flag NOT Set |\n");

    if(packet->urg == 1){
        printf("   |   URG Flag Set   |\n");
    } else printf("   | URG Flag NOT Set |\n");
    printf("   |__________________|\n\n");
}



void decode_ipvx(const struct ip *packet){
    printf("   | Header Length: %u bytes\n", packet->ip_hl);
    printf("   | Total Length: %u bytes\n", packet->ip_len);
    printf("   | Protocol: %u\n", packet->ip_p);
}

void writef(const packetData pack, char src_ip[INET6_ADDRSTRLEN], char dst_ip[INET6_ADDRSTRLEN]){
    fprintf(fp, "time <%s>", pack.time);
    fprintf(fp, "length <%u> bytes\n", pack.ip_header->ip_len);
    fprintf(fp, "protocol <%u>\n", pack.ip_header->ip_p);
    fprintf(fp, "src_ip <%s>\ndst_ip <%s>\n\n", src_ip, dst_ip);
}

void tcpwritef(const struct tcphdr *packet){
    fprintf(fp,"\nFLAGS\n");
    if(packet->syn == 1){
        fprintf(fp,"   |   SYN Flag Set   |\n");
    } else fprintf(fp,"   | SYN Flag NOT Set |\n");

    if(packet->rst == 1){
        fprintf(fp,"   |   RST Flag Set   |\n");
    } else fprintf(fp,"   | RST Flag NOT Set |\n");

    if(packet->psh == 1){
        fprintf(fp,"   |   PSH Flag Set   |\n");
    } else fprintf(fp,"   | PSH Flag NOT Set |\n");

    if(packet->ack == 1){
        fprintf(fp,"   |   ACK Flag Set   |\n");
    } else fprintf(fp,"   | ACK Flag NOT Set |\n");

    if(packet->urg == 1){
        fprintf(fp,"   |   URG Flag Set   |\n");
    } else fprintf(fp,"   | URG Flag NOT Set |\n\n");
}

/*
void decode_ipv4(const u_char *packet){

    int version = (packet[0] & 0xf0) >> 4;
    int header_length = (packet[0] & 0x0f) * 4;
    int total_length = packet[2] << 8 | packet[3];
    int protocol = packet[9];
    char source_ip[INET_ADDRSTRLEN];
    char dest_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, packet + 12, source_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, packet + 16, dest_ip, INET_ADDRSTRLEN);

    printf("IPv4 Packet:\n");
    printf("    | Version: %d\n", version);
    printf("    | Header Length: %d bytes\n", header_length);
    printf("    | Total Length: %d bytes\n", total_length);
    printf("    | Protocol: %d\n", protocol);
    printf("    | Source IP Address: %s\n", source_ip);
    printf("    | Destination IP Address: %s\n", dest_ip);
}
*/

#endif