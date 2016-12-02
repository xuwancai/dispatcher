#include <stdio.h>
#include <pcap.h>

unsigned char packet[] = {
                0x52,0x54,0x00,0x06,0x43,0xd7,0xfe,0x54,0x00,0x06,0x43,0xd7,0x08,0x00,\
                0x45,0x00,0x00,0x80,0x95,0x11,0x00,0x00,0x3f,0x01,0x8b,0x5b,0xc2,0x88,0x51,0xde,\
                0x46,0x00,0x00,0xaa,0x00,0x00,0x32,0,0,0,0,0,1,2,3,4,5,6,7,8,9,10,\
                11,12,13,14,15,16,17,18,19,20,\
                21,22,23,24,25,26,27,28,29,30,\
                31,32,33,34,35,36,37,38,39,40,\
                41,42,43,44,45,46,47,48,49,50,\
                51,52,53,54,55,56,57,58,59,60,\
                61,62,63,64,65,66,67,68,69,70,\
                71,72,73,74,75,76,77,78,79,80,\
                81,82,83,84,85,86,87,88,89,90,\
                91,92,93,94,95,96,97,98,99,100};

void handle_recv(u_char* argument,const struct pcap_pkthdr* packet_header,const u_char* packet_content)
{
    static unsigned long long recv = 0;
    recv++;
    if (recv % 1000 == 0) {
        printf("pcap recv num %d=", recv);
        fflush(stdout);
    }

    return;
}
                
int main(int argc, char* argv[]) 
{
    int i;
    int found = 0;
    pcap_if_t *alldevs;
    pcap_if_t *dev_if;
    pcap_t* dev;
	char err[PCAP_ERRBUF_SIZE] = {0};

    if (argc != 3) {
        printf("usage ./pcap eth0 [recv/send]\n");
        return -1;   
    }

    if (pcap_findalldevs(&alldevs, err) == -1) {
        printf("pcap_findalldevs error");
    }

    for (dev_if = alldevs; dev_if!= NULL; dev_if = dev_if->next) {
        if (strcmp(dev_if->name, argv[1]) == 0) 
            found = 1;
    }
    if (found == 0) {
        printf("not found nic %s, list all nic name:\n", argv[1]);
        for (dev_if = alldevs; dev_if!= NULL; dev_if = dev_if->next)
            printf("%s\n", dev_if->name);
        return -1;
    }

    dev = pcap_open_live(argv[1], BUFSIZ, 1, -1, err);
    if (dev == NULL)
        printf("pcap_open_live %s err\n", argv[1]);

    if (strcmp(argv[2], "recv") == 0) {
        while (1) {
            pcap_loop(dev, -1, handle_recv, NULL);
        }
    } else {
        while (1) {
            for(i = 0; i< 1000; ++i) {
                if (pcap_sendpacket(dev, packet , sizeof(packet)) != 0) {
                    printf("send error\n");
                    return -1;
                }
            }
            sleep(1);
        }
    }
    
    pcap_close(dev);
    pcap_freealldevs(alldevs);
    return 0;
}
