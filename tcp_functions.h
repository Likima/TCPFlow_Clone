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

void decode_tcp(const struct tcphdr *packet){
    printf("   |   | Source Port: %hu\n", packet->source);
    printf("   |   | Destination Port: %hu\n", packet->dest);
    printf("   |   | Sequence Number: %d\n", packet->seq);
    printf("   |   | Acknowledgement Number: %d\n", ntohl(packet->ack_seq));
    printf("   |   | Data Offset: %hu\n", packet->doff);

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

void decode_ipv4(const struct ip *packet){
    printf("   | Header Length: %d bytes\n", packet->ip_hl);
    printf("   | Total Length: %d bytes\n", packet->ip_len);
    printf("   | Protocol: %d\n", packet->ip_p);
}

void decode_ipv6(const struct ip *packet){

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