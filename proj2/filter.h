/*************************
 *     IPK 2019/2020
 * Daša Nosková xnosko05
 *************************/
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <string.h>
#include <time.h>

#define ETHERNET_SIZE sizeof(struct ethhdr)
#define HEX 16
#define MAX_TIME 101
#define MAX_IP_SIZE 20


/* returns in pointers *src and *dst sources and destinations IP addresses */
void get_src_dst_addr(char *src, char *dst, struct iphdr *iph);
/* returns in pointers *src_port and *dst_port number of the ports */
void get_port(const u_char *packet,struct iphdr *iph, char *type, unsigned short *src_port,
              unsigned short *dst_port);
/* checks for protocol tcp/udp
   in case it's different protocol, just writes unknown protocol. */
void check_protocol(const u_char *packet,  struct iphdr *iph, unsigned short *src_port,
                    unsigned short *dst_port);
/* converts value in variable val to ascii character
   in case value is printable character, converts the character to its ascii value,
   in case value is not printable character, value is interpreted as a dot '.'
   appends each value to string of these values
   returns converted string in pointer *ascii_str     */
void convert_ascii(char *ascii_str, unsigned int val);
/*  Prints data from packet to output.
    X represents Xth "line" of packet. */
void print_packet(const u_char* packet, unsigned X);
/* Prints out packet header and packet output. */
void process_packet(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet);
/* Function sniffs number of given packets at given interface.
 * Prints them to output. */
int sniff(char *interface, int no_packets, int port, char* protocol);