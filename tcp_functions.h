#ifndef TCP_FUNCTIONS_H
#define TCP_FUNCTIONS_H
#include "packet_capture.h"

void decode_ipv4(const u_char *packet)
{
    // Extract the IP header fields
    int version = (packet[0] & 0xf0) >> 4;
    int header_length = (packet[0] & 0x0f) * 4;
    int total_length = packet[2] << 8 | packet[3];
    int protocol = packet[9];
    char source_ip[INET_ADDRSTRLEN];
    char dest_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, packet + 12, source_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, packet + 16, dest_ip, INET_ADDRSTRLEN);

    // Print the IP header fields
    printf("IPv4 Packet:\n");
    printf("Version: %d\n", version);
    printf("Header Length: %d bytes\n", header_length);
    printf("Total Length: %d bytes\n", total_length);
    printf("Protocol: %d\n", protocol);
    printf("Source IP Address: %s\n", source_ip);
    printf("Destination IP Address: %s\n", dest_ip);
}

#endif