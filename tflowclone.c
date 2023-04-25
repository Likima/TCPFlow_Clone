#include "packet_capture.h"
#include "tcp_functions.h"
#include "initial.h"

/*TCP FLOW CLONE PROJECT
Captures TCP packets... maybe more
Terminated by ctrl+c
--improve xml file generator
--organize git better
mac_daddr: destination address
mac_saddr: source address 
https://en.wikipedia.org/wiki/Transmission_Control_Protocol
--zlib
--sudo tcpflow port 80 and host shinyslowfinemagic.neverssl.com
--implement zlib decoding
--look for 2 \n chars and then it is gzip encoded
*/

int main(int argc, char* argv[]){
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle;
    char* net; char* dev; char* mask;
    char* filter_exp = "tcp";
    struct pcap_pkthdr header;
    struct in_addr addr;
    struct bpf_program filter;
    const u_char *packet;
    bpf_u_int32 netp; bpf_u_int32 maskp;
    int promisc = 0;
    signal(SIGINT, sigint_handler);

    for(int x = 1; x<argc; x=x+1){
        /*
        if(strcmp(argv[x], "-w")==0){
            if(x == argc - 1){
                printf("Invalid usage of -w, no file provided. SYNTAX: ./tflowclone -w <filename>\n");
                exit(1);
            }
            argPointer = argv[x+1];
            len = strlen(argPointer);
            if (len >= 4 && strcmp(argPointer + len - 4, ".txt") != 0) strcat(argv[x+1], ".txt");

            fp = fopen(argv[x+1], "w+");
            if(fp == NULL){
                printf("Invalid usage of -w, file %s provided does not exist\n", *argv[x+1]);
                exit(1);
            }
        */
        if(strcmp(argv[x], "-a")==0){
            printf("creating html\n");

        }

        if(strcmp(argv[x], "-p")==0){
            promisc = 1;
            printf("Set To Promiscuous Mode\n\n");
            continue;
        }       
        else if(strcmp(argv[x], "-e")==0){
            if(x == argc - 1){
                printf("Invalid usage of -e, provide filter expression\n");
                exit(1);
            } else filter_exp = argv[x+1];
            //fp = fopen(argv[x+1], "w+");         
            x=x+1;
            continue;
        }
        else if(strcmp(argv[x], "-c")==0){
            printf("Printing To Console...\n");
            cprint = !cprint;
        }
    }
    dev = pcap_lookupdev(errbuf);
    if(dev == NULL){
        printf("%s\n", errbuf);
        exit(1);
    }
    printf("Listening On Device: %s\n\n", dev);
   //promiscuous mode denoted by the 1, meaning that it captures ALL network traffic
    handle = pcap_open_live(dev, BUFSIZ, promisc, 1000, errbuf);
    if(handle == NULL){
        fprintf(stderr, "Could not open device: %s\n", errbuf);
        return 1;
    }
    if(pcap_compile(handle, &filter, filter_exp, 0, netp) == -1) {//1 denotes speed; 0 denotes size
        fprintf(stderr, "Couldn't compile filter: %s\n", pcap_geterr(handle));//filters and checks on one line
        return 1;
    }
    if(pcap_setfilter(handle, &filter) == -1) {
        fprintf(stderr, "Couldn't set filter: %s\n", pcap_geterr(handle));
        return 1;
    }

    if (access("report.xml", F_OK) != 0) {
        system("touch report.xml");
    }
    
    fp = fopen("report.xml", "a+");


    fseek (fp, 0, SEEK_END);
    if(ftell(fp) == 0){
        fprintf (fp,"<?xml version=\"1.0\" encoding=\"utf-8\"?>\n");
        //initialize();
    }
    
    pcap_loop(handle, 0, packet_handler, NULL);
    pcap_freecode(&filter);
    pcap_close(handle);

    return(0);
}

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data){
    packetData pack;
    size_t len;
    struct tcphdr *tPacket;
    struct udphdr *uPacket;
    struct iphdr *iph = (struct iphdr*)(pkt_data + sizeof(struct ethhdr));
    char *httppack = NULL;
    char comb[BUFSIZ];
    char *file_name = NULL;
    char *combInfo;
    char ipfname[BUFSIZ];
    char info;
    u_char *rawbdata;
    char src_ip[INET6_ADDRSTRLEN];
    char dst_ip[INET6_ADDRSTRLEN];
    int size;
    int tick = 1;
    int payload_size;
    int payload_off;
    pack.header = header;
    pack.time = ctime((const time_t *)&header->ts.tv_sec);
    pack.ip_header = (struct ip*)(pkt_data + sizeof(struct ether_header));
    //info = (u_char *)malloc(1000 * sizeof(u_char));
__HAVE_FLOAT64X_LONG_DOUBLE

    printf("----------------------------------------\n");
    if(pack.ip_header->ip_v == 4){
        inet_ntop(AF_INET, &(pack.ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(pack.ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);

    } else if(pack.ip_header->ip_v==6){
        inet_ntop(AF_INET6, &(pack.ip_header->ip_src), src_ip, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &(pack.ip_header->ip_dst), dst_ip, INET6_ADDRSTRLEN);

    }else{
        printf("UNKOWN PACKET TYPE\n");
        exit(1);
    }
    //if(cprint) decode_ipvx(pack.ip_header);

    if(pack.ip_header->ip_p==6){
        tPacket = (struct tcphdr*)(pkt_data + sizeof(struct iphdr)+ sizeof(struct ethhdr));
        snprintf(ipfname, BUFSIZ+1, "%s.%hu-%s.%hu.txt", src_ip, ntohs(tPacket->source), dst_ip, ntohs(tPacket->dest));
        printf("FNAME: %s\n", ipfname);
        if(access(ipfname, F_OK) == 0){
            ipfp = fopen(ipfname, "ab");
        }else{
            snprintf(comb, BUFSIZ+1, "touch %s", ipfname);
            system(comb);
            ipfp = fopen(ipfname, "wb");
        }

        strcpy(info, ((const char*)(pkt_data+sizeof(struct ethhdr) + pack.ip_header->ip_hl*4 + tPacket->doff*4)));
        printf("%d\n", isHttpHeader(info));
        //size = strlen(info);

        if(cprint){
            decode_tcp(tPacket);
            printf("%.*s\n\n", (header->len)-(tPacket->doff*4), info);
        }
        //fprintf(ipfp, "%.*s\n", (header->len)-(tPacket->doff*4), info);
        if(isHttpHeader(info) == 0){
            fprintf(ipfp, info);

            //for (int i = 0; i<size != '\0'; i++) {
            //    fprintf(ipfp, "%02x ", rawbdata[i]); // Print each byte in hexadecimal format with leading zeros
            //}
        }else fprintf(ipfp, "%.*s\n", (header->len)-(tPacket->doff*4), info);
        //free(info);
        fclose(ipfp);
        ipfp = NULL;
    }

    if(pack.ip_header->ip_p == 17 || pack.ip_header->ip_p == 128){
        uPacket = (struct udphdr*)(pkt_data + sizeof(struct ether_header));
        if(cprint) decode_udp(uPacket);
    }
    
    if(cprint){
        printf("   | Source IP: %s\n", src_ip);
        printf("   | Destination IP: %s\n", dst_ip);
        printf("   | Packet length: %d\n", pack.header->len);
        printf("   | Packet timestamp: %s\n\n", pack.time);
    }
    printf("-------------------------------------\n");
    
    if(fp != NULL){
        writef(pack, src_ip, dst_ip);
        if(pack.ip_header->ip_p == 6) tcpwritef(tPacket);
    }
    
}