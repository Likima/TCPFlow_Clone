#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>

//TCP FLOW CLONE PROJECT

int main(int *argc, char** argv){
    //VARS----------------------------------
    char* errbuff[PCAP_ERRBUF_SIZE];
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
    dev = pcap_lookupdev(errbuff);

    if(dev == NULL){
        printf("%s\n", errbuff);
        return(1);
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

    return(0);


}
