#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>

/*TCP FLOW CLONE PROJECT
Captures TCP packets in a loop
Terminated by ctrl+c
*/

typedef struct{
    char** argv;
    int argc;
}cast_var;

void packet_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *pkt_data){
    cast_var* args = (cast_var*) user; //passed to function as a void pointer. Converts to a usable pointer
    char** argv = args->argv;
    int argc = args->argc;

    for(int x = 1; x<argc; x++){
        printf("Argument %d: %s\n", x, argv[x]);
    }
}

int main(int argc, char* argv[]){
    //VARS----------------------------------
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle;
    char* dev;
    char* net;
    char* mask;
    struct pcap_pkthdr header;
    struct in_addr addr;
    struct bpf_program filter;
    const u_char *packet;
    bpf_u_int32 netp, maskp;
    cast_var usrarg;
    //---------------------------------------
    usrarg.argv = argv;
    usrarg.argc = argc;
    printf("%d\n",argc);

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

    pcap_loop(handle, 0, packet_handler,(u_char *) &usrarg);

    pcap_close(handle);

    return(0);


}
