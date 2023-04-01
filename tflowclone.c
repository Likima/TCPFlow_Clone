#include "packet_capture.h"
#include "tcp_functions.h"
#include "xmlwrite.h"

/*TCP FLOW CLONE PROJECT
Captures TCP packets in a loop
Terminated by ctrl+c
--create xml file generator
--organize git better
--make payload human readable (non encrypted) http packets (tcp port 80)
mac_daddr: destination address
mac_saddr: source address 
https://en.wikipedia.org/wiki/Transmission_Control_Protocol
--zlip
--sudo tcpflow port 80 and host shinyslowfinemagic.neverssl.com
--debug tcp packet
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
    int len;
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
    }
    dev = pcap_lookupdev(errbuf);
    if(dev == NULL){
        printf("%s\n", errbuf);
        exit(1);
    }
    printf("DEVNAME: %s\n", dev);
    addr.s_addr = netp;
    net = inet_ntoa(addr);//converts addr (in inet) to ascii
    if(net == NULL){
        perror("inet_ntoa");
        exit(1);
    }
    printf("NET: %s\n", net);
    addr.s_addr = maskp;
    mask = inet_ntoa(addr);
    if(mask == NULL){
        perror("inet_ntoa");
        exit(1);
    }
    printf("MASK: %s\n\n", mask);
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
        system(CREATE_FILE);
    }
    fp = fopen("report.xml", "a+");


    fseek (fp, 0, SEEK_END);
    if(ftell(fp) == 0){
        fprintf (fp,"<?xml version=\"1.0\" encoding=\"utf-8\"?>\n");
        initialize();
    }
    pcap_loop(handle, 0, packet_handler, NULL);
    pcap_freecode(&filter);
    pcap_close(handle);

    return(0);
}

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data){
    packetData pack;
    struct tcphdr *tPacket;
    struct udphdr *uPacket;
    char src_ip[INET6_ADDRSTRLEN];
    char dst_ip[INET6_ADDRSTRLEN];
    pack.header = header;
    pack.time = ctime((const time_t *)&header->ts.tv_sec);
    pack.ip_header = (struct ip*)(pkt_data + sizeof(struct ether_header)); //fancy way of saying 14
    //ethernet header are the bytes up to 14
    //ip header is the next 20 bytes
    printf("Payload Length: %d\n", header->len);
    printf("Packet Payload: ");
    for (int i = 0; i < header->len; i++){
        printf("%02x ", pkt_data[i]);
    }
    
    printf("\n");
    
    //checking for ip version
    if(pack.ip_header->ip_v == 4){
        printf("IPv4 Packet\n");
        inet_ntop(AF_INET, &(pack.ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(pack.ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);

    } else if(pack.ip_header->ip_v==6){
        printf("IPv6 Packet\n");
        inet_ntop(AF_INET6, &(pack.ip_header->ip_src), src_ip, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &(pack.ip_header->ip_dst), dst_ip, INET6_ADDRSTRLEN);

    } else{
        printf("UNKOWN PACKET TYPE\n");//as of rn
        exit(1);
    }
    decode_ipvx(pack.ip_header);

    if(pack.ip_header->ip_p==6){
        printf("   |   | TCP PACKET\n");
        //tPacket = (struct tcphdr*)(pkt_data + sizeof(struct ether_header)+(pack.ip_header->ip_hl*4));
        tPacket = (struct tcphdr*)(pkt_data + sizeof(struct iphdr));
        //tPacket = (struct tcphdr *)(pkt_data + 20);
        fprintf(fp, "%.*s\n", header->len-tPacket->doff*4, (const char*) pkt_data+tPacket->doff*4);
        decode_tcp(tPacket);
        printf("THIS IS THE DECODED:\n");
        //printf("%s\n", (const char*)(pkt_data+tPacket->doff*4));
        printf( "%.*s\n", (header->len)-(tPacket->doff*4), (const char*)(pkt_data+sizeof(struct ethhdr) + pack.ip_header->ip_hl*4 + tPacket->doff*4));

    }
    if(pack.ip_header->ip_p == 17 || pack.ip_header->ip_p == 128){
        printf("   |   | UDP PACKET\n");
        uPacket = (struct udphdr*)(pkt_data + sizeof(struct ether_header));
        decode_udp(uPacket);

    }
    
    //printInfo(pack, src_ip, dst_ip);
    printf("   | Source IP: %s\n", src_ip);
    printf("   | Destination IP: %s\n", dst_ip);
    printf("   | Packet length: %d\n", pack.header->len);
    printf("   | Packet timestamp: %s\n\n", pack.time);

    if(fp != NULL){
        writef(pack, src_ip, dst_ip);
        if(pack.ip_header->ip_p == 6) tcpwritef(tPacket);
    }
}