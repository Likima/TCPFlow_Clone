#ifndef TCP_FUNCTIONS_H
#define TCP_FUNCTIONS_H
#include "packet_capture.h"

void sigint_handler(int sig) {
    printf("\nTerminating...\n");
    if(fp != NULL) fclose(fp);
    if(ipfp != NULL) fclose(ipfp);
    exit(0);
}

void decode_udp(const struct udphdr *packet){
    printf("   |   | Source: %hu\n", packet->source);
    printf("   |   | Destination: %hu\n", packet->dest);
    printf("   |   | Length: %hu\n", packet->len);
    printf("   |   | Check: %hu\n", packet->check);
}

void decode_tcp(const struct tcphdr *packet){
    printf("   |   | Source Port: %hu\n", ntohs(packet->source));
    printf("   |   | Destination Port: %hu\n", ntohs(packet->dest));
    printf("   |   | Sequence Number: %u\n", ntohl(packet->seq));
    printf("   |   | Acknowledgement Number: %u\n", ntohl(packet->ack_seq));
    printf("   |   | Data Offset: %d\n", packet->doff);

    printf("\nFLAGS: ");
    if(packet->syn == 1){
        printf("SYN Flag Set, ");
    } else printf("SYN Flag NOT Set, ");

    if(packet->rst == 1){
        printf("RST Flag Set, ");
    } else printf("RST Flag NOT Set, ");

    if(packet->psh == 1){
        printf("PSH Flag Set, ");
    } else printf("PSH Flag NOT Set, ");

    if(packet->ack == 1){
        printf("ACK Flag Set, ");
    } else printf("ACK Flag NOT Set, ");

    if(packet->urg == 1){
        printf("URG Flag Set\n\n");
    } else printf("URG Flag NOT Set\n\ns");
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
    fprintf(fp, "   |   | Source Port: %u\n", ntohs(packet->source));
    fprintf(fp, "   |   | Destination Port: %u\n", ntohs(packet->dest));
    fprintf(fp, "   |   | Sequence Number: %u\n", ntohl(packet->seq));
    fprintf(fp, "   |   | Acknowledgement Number: %u\n", ntohl(packet->ack_seq));
    fprintf(fp, "   |   | Data Offset: %d\n", packet->doff);

    fprintf(fp, "\nFLAGS: ");
    if(packet->syn == 1){
        fprintf(fp, "SYN Flag Set, ");
    } else fprintf(fp, "SYN Flag NOT Set, ");

    if(packet->rst == 1){
        fprintf(fp, "RST Flag Set, ");
    } else fprintf(fp, "RST Flag NOT Set, ");

    if(packet->psh == 1){
        fprintf(fp, "PSH Flag Set, ");
    } else fprintf(fp, "PSH Flag NOT Set, ");

    if(packet->ack == 1){
        fprintf(fp, "ACK Flag Set, ");
    } else fprintf(fp, "ACK Flag NOT Set, ");

    if(packet->urg == 1){
        fprintf(fp, "URG Flag Set\n");
    } else fprintf(fp, "URG Flag NOT Set\n");
}

void postDeletion() {
    FILE* file;
    char fileName[256]; // Maximum length of a file name
    int removedCount = 0; // Counter to keep track of the number of removed files

    // Open the current directory
    DIR* dir = opendir(".");
    if (dir == NULL) {
        printf("Failed to open current directory.\n");
        return;
    }

    // Loop through each file in the current directory
    struct dirent* entry;
    while ((entry = readdir(dir)) != NULL) {
        // Ignore "." and ".." directories
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        // Construct the file path
        snprintf(fileName, sizeof(fileName), "%s", entry->d_name);

        // Attempt to open the file for reading
        file = fopen(fileName, "r");
        if (file == NULL) {
            // Failed to open the file, remove it
            if (remove(fileName) == 0) {
                printf("Removed: %s\n", fileName);
                removedCount++;
            } else {
                printf("Failed to remove: %s\n", fileName);
            }
        } else {
            // File is opened successfully, check if it's empty
            fseek(file, 0, SEEK_END);
            long fileSize = ftell(file);
            fclose(file);
            if (fileSize == 0) {
                // Empty file, remove it
                if (remove(fileName) == 0) {
                    printf("Removed: %s\n", fileName);
                    removedCount++;
                } else {
                    printf("Failed to remove: %s\n", fileName);
                }
            }
        }
    }

    // Close the directory
    closedir(dir);

    printf("Total removed files: %d\n", removedCount);
}
/*
int decompress_packet(const u_char* packet, uLongf packet_len){
    uLongf destlen = BUFSIZE;
    Bytef dest[BUFSIZE];
    z_stream strm;
    int ret;

    // Initialize the z_stream structure
    memset(&strm, 0, sizeof(strm));
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    strm.avail_in = packet_len;
    strm.next_in = (Bytef *)packet;

    // Check if the packet is Gzip-encoded
    if (packet[0] == 0x1F && packet[1] == 0x8B) {
        // Initialize the gzip decompression
        ret = inflateInit2(&strm, 16+MAX_WBITS);
        if (ret != Z_OK) {
            fprintf(stderr, "Error initializing gzip decompression\n");
            return -1;
        }

        // Decompress the packet data
        do {
            strm.avail_out = destlen;
            strm.next_out = dest;
            ret = inflate(&strm, Z_SYNC_FLUSH);
            if (ret == Z_STREAM_ERROR) {
                fprintf(stderr, "Error in gzip decompression\n");
                inflateEnd(&strm);
                return -1;
            }

            // Write the uncompressed data to stdout
            printf(dest);
            //fwrite(dest, 1, destlen-strm.avail_out, stdout);
        } while (strm.avail_out == 0);

        // Clean up the zlib structures
        inflateEnd(&strm);
    } else {
        // The packet is not Gzip-encoded, so print it as is
        printf(packet);
        //fwrite(packet, 1, packet_len, stdout);
    }

    return 0;
}
*/

#endif