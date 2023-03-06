#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>

//TCP FLOW CLONE PROJECT

void packet_analyze(){

}


int main(int argc, char** argv){
    //VARS----------------------------------
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle;
    char* dev;
    char* net;
    char* mask;
    struct pcap_pkthdr header;
    struct in_addr addr;
    struct bpf_program filter;
    char filter_exp[] = "tcp";
    const u_char *packet;
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
    printf("Listening On Device: %s\n\n", dev);

    //--------------------------------------------

    /*
    verifying terminal input works
    if(argc != 0){
        printf("%s\n", argv[1]);
    }
    */

   //promiscuous mode denoted by the 1, meaning that it captures ALL network traffic
   handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if(handle == NULL){
        fprintf(stderr, "Could not open device: %s\n", errbuf);
        return(1);
    }


   if(argc == 0){
        while(1){
            pcap_compile(handle, &filter, filter_exp, 1, PCAP_NETMASK_UNKNOWN);
            packet = pcap_next(handle, &header); //actually captures the packet
            if(packet != NULL){
                
            }
        }
   }


    return(0);


}
