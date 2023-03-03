#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>

//TCP FLOW CLONE PROJECT

int main(int argc, char** argv){
    //VARS----------------------------------
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle;
    char* dev;
    char* net;
    char* mask;
    //struct pcap_pkthdr header;
    struct in_addr addr;
    //const u_char *packet;
    bpf_u_int32 netp; 
    bpf_u_int32 maskp;
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

    printf("Listening On Device: %s\n", dev);




    return(0);


}
