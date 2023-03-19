#include "packet_capture.h"

/*TCP FLOW CLONE PROJECT
Captures TCP packets in a loop
Terminated by ctrl+c
--Code "h" function to display a help menu
--Make sure to get commands with -
--code -w TCPFLOW function
*/

void sigint_handler(int);
void packet_handler(u_char*, const struct pcap_pkthdr*, const u_char*);

int main(int argc, char* argv[]){
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle;
    char* net; char* dev; char* mask;
    struct pcap_pkthdr header;
    struct in_addr addr;
    struct bpf_program filter;
    const u_char *packet;
    bpf_u_int32 netp; bpf_u_int32 maskp;
    cast_var usrarg;
    int promisc = 0;
    char* argPointer;
    int len;
    char cpy[100];
    usrarg.argv = argv;
    usrarg.argc = argc;

    for(int x = 1; x<argc; x=x+1){
        if(isdigit(*argv[x]) != 0){
            if(atoi(argv[x]) == 0 || atoi(argv[x]) == 1){
                promisc = atoi(argv[x]);
                continue;
            } else {
                printf("Promiscuous denoted by 0 or 1\n");
                exit(1);
            }
        }

        if(strcmp(argv[x], "-w")==0){
            if(x == argc - 1){
                printf("Invalid usage of -w, no file provided. SYNTAX: ./tflowclone -w <filename>\n");
                exit(1);
            }
            argPointer = argv[x+1];
            len = strlen(argPointer);
            if (len >= 4 && strcmp(argPointer + len - 4, ".txt") != 0) strcat(argv[x+1], ".txt");

            fp = fopen(strcpy(cpy, argv[x+1]), "w+");
            if(fp == NULL){
                printf("Invalid usage of -w, file %s provided does not exist\n", *argv[x+1]);
                exit(1);
            }
            
            x=x+1;
            signal(SIGINT, sigint_handler);
        //add later in the code; is used to add the -w functionality
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
    if(mask == NULL)
    {
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
    //FILTERING TCP PACKETS ONLY
    if(pcap_compile(handle, &filter, "tcp", 1, netp) == -1) {//1 denotes speed; 0 denotes size
        fprintf(stderr, "Couldn't compile filter: %s\n", pcap_geterr(handle));
        return 1;
    }
    if(pcap_setfilter(handle, &filter) == -1) {
        fprintf(stderr, "Couldn't set filter: %s\n", pcap_geterr(handle));
        return 1;
    }    

    pcap_loop(handle, 0, packet_handler,(u_char *) &usrarg);
    pcap_close(handle);

    return(0);
}

void sigint_handler(int sig) {
    printf("\nTerminating...\n");
    if(fp != NULL) fclose(fp);
    exit(0);
}
/*
void file_writer(u_char *user, const struct pcap_pkthdr *header, const u_char *pkt_data){


    return 0;
}
*/
void packet_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *pkt_data){
    const u_char *packet;
    const struct ip *ip_header;
    struct pcap_pkthdr hdr;
    cast_var* args = (cast_var*) user; //passed to function as a void pointer. Converts to a usable pointer
    //packetData data;
    char** argv = args->argv;
    int argc = args->argc;

    char* timestamp_str = ctime((const time_t *)&header->ts.tv_sec);

    ip_header = (struct ip*)(pkt_data + sizeof(struct ether_header));

    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);

    printf("Source IP: %s\n", src_ip);
    printf("Destination IP: %s\n", dst_ip);
    printf("Packet length: %d\n", header->len);
    printf("Packet timestamp: %s\n\n", timestamp_str);
    /*
    if(fp != NULL){
        fprintf(fp, "---NEW PACKET---\nTIME CAPTURED: ");
        fprintf(fp, "%s", timestamp_str);
        fprintf(fp, "PACKET LENGTH: ");
        fprintf(fp, "%d\n\n", header->len);
    }
    //write function in separate .h file to do this
    */

        //printf("Packet timestamp: %s\n", ctime((const time_t *)&header->ts.tv_sec));

}