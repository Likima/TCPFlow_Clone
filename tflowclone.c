#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>

/*TCP FLOW CLONE PROJECT
Captures TCP packets in a loop
Terminated by ctrl+c
*/

typedef struct{
    char** strings;
    int len;
} list;

void packet_analyze(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data, ){


}

int main(u_char *user, int argc, char** argv){
    //VARS----------------------------------
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle;
    char* dev, net, mask;
    struct pcap_pkthdr header;
    struct in_addr addr;
    struct bpf_program filter;
    const u_char *packet;
    bpf_u_int32 netp, maskp;
    //---------------------------------------
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
    printf("MASK: %s\n", mask);
    printf("Listening On Device: %s\n\n", dev);

   //promiscuous mode denoted by the 1, meaning that it captures ALL network traffic
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if(handle == NULL){
        fprintf(stderr, "Could not open device: %s\n", errbuf);
        return 1;
    }

    //FILTERING TCP PACKETS ONLY

    if (pcap_compile(handle, &filter, "tcp", 1, net) == -1) {
        fprintf(stderr, "Couldn't compile filter: %s\n", pcap_geterr(handle));
        return 1;
    }

    if (pcap_setfilter(handle, &filter) == -1) {
        fprintf(stderr, "Couldn't set filter: %s\n", pcap_geterr(handle));
        return 1;
    }    

    //--------

    pcap_loop(handle, 0, packet_analyze, (u_char *)argv)

    /*
    if(argc == 0){
        while(1){
            pcap_compile(handle, &filter, filter_exp, 1, PCAP_NETMASK_UNKNOWN);
            packet = pcap_next(handle, &header); //captures the packet
            if(packet != NULL){
                packet_analyze(packet, );
            }
        }
   }
    */

    return(0);


}
