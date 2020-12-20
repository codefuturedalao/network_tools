#ifndef ARP
#define ARP
#include <pcap/pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#define GREP_MAC "grep -o -E '([[:xdigit:]]{1,2}:){5}[[:xdigit:]]{1,2}'" //regex to extract the mac address from a given output with MAC address in it
#define MAC_FORMAT "%02hhX:%02hhX:%02hhX:%02hhX:%02hhX:%02hhX"
#define ARP_QUERY 0x0001
#define ARP_ANS   0x0002
#define TIME_INTERVAL 5            // time interval to send an ARP reply to the victim to keep him poisoned


//color macro definition
#define CLOSE(); printf("\033[0m"); //关闭彩色字体
#define RED(); printf("\033[31m"); //红色字体
#define GREEN(); printf("\033[32m");//绿色字体
#define YELLOW(); printf("\033[33m");//黄色字体
#define BLUE(); printf("\033[34m");//蓝色字体

//type definition
typedef enum{false, true} bool;
typedef struct ether_header Ethh;
typedef struct arp_header
{
    u_int16_t       hw_type;                /* Format of hardware address  */
    u_int16_t       protocol_type;          /* Format of protocol address  */
    u_int8_t        hw_len;                 /* Length of hardware address  */
    u_int8_t        protocol_len;           /* Length of protocol address  */
    u_int16_t       opcode;                 /* ARP opcode (command)  */
    u_int8_t        src_mac[ETH_ALEN];   /* Sender hardware address  */
    u_int8_t        src_ip[4];           /* Sender IP address  */ 
    u_int8_t        dst_mac[ETH_ALEN];   /* Target hardware address  */
    u_int8_t        dst_ip[4];           /* Target IP address  */
} Arph;

typedef struct arpspf {
    struct ether_addr interface_mac;
    struct in_addr interface_ip;
    struct ether_addr victim_mac;
    struct in_addr victim_ip;
    struct ether_addr gateway_mac;
    struct in_addr gateway_ip;
} Arpspf;



//global variable
Arpspf my_arp;
char error_buffer[PCAP_ERRBUF_SIZE];
pcap_if_t *dev_list;
struct timeval tv, checktv;

//fucntion
int Start_Timer(struct timeval *tv, time_t sec);
int Check_Timer(time_t sec);
void get_dev_list(pcap_if_t **pdev_list);
void show_dev_list(pcap_if_t *dev_list);
bool get_ip(char *interface, struct in_addr *ip);
bool get_mac_from_terminal(char *interface, struct ether_addr *mac_addr);
bool get_gateway_ip(struct in_addr* gateway_ip);
void send_arp_packet(pcap_t *handle, struct ether_addr *src_mac, struct in_addr *src_ip, struct ether_addr *dst_mac, struct in_addr *dst_ip,  u_int16_t packet_type);
void handle_packet(u_char* arg, const struct pcap_pkthdr* pkthdr, const u_char* packet);
void handle_ip(u_char* arg, const struct pcap_pkthdr* pkthdr, const u_char* packet);
void handle_arp(u_char* arg, const struct pcap_pkthdr* pkthdr, const u_char* packet);
void get_mac_from_arp(u_char *packet, struct ether_addr *mac);

#endif
