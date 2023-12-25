/*************************
 *     IPK 2019/2020
 * Daša Nosková xnosko05
 *************************/

#include <pcap/pcap.h>

#include "filter.h"
#include "error.h"

int no_bytes;

void get_src_dst_addr(char *src, char *dst, struct iphdr *iph) {

    struct sockaddr_in source, dest;

    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;

    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;

    strcpy(src, inet_ntoa(source.sin_addr));
    strcpy(dst, inet_ntoa(dest.sin_addr));

}

void get_port(const u_char *packet,struct iphdr *iph, char *type, unsigned short *src_port,
              unsigned short *dst_port) {

    //X + SIZE_ETHERNET + {IP header length}
    unsigned short iphdrlen = iph->ihl*4;

    if (!strcmp(type, "tcp")) {
        struct tcphdr *tcph=(struct tcphdr*)(packet + iphdrlen + ETHERNET_SIZE);
        *src_port = ntohs(tcph->source);
        *dst_port = ntohs(tcph->dest);
    }
    else if (!strcmp(type, "udp")) {
        struct udphdr *udph = (struct udphdr*)(packet + iphdrlen  + ETHERNET_SIZE);
        *src_port = ntohs(udph->source);
        *dst_port = ntohs(udph->dest);
    }

}

void check_protocol(const u_char *packet,  struct iphdr *iph, unsigned short *src_port,
                    unsigned short *dst_port) {
    //	X + SIZE_ETHERNET
    switch (iph->protocol) {
        case 6: //tcp
            get_port(packet,iph,"tcp", src_port, dst_port);
            break;
        case 17: //udp
            get_port(packet,iph,"udp", src_port, dst_port);
            break;
        default:
            printf("Different protocol than tcp/udp.");
    }
}

void convert_ascii(char *ascii_str, unsigned int val) {
    char ascii_val[16] = "";
    unsigned int decimal = val; //decimal
    if (32 <= decimal && decimal < 127) { //printable chars
        sprintf(ascii_val,"%c",val);
        strcat(ascii_str,ascii_val);
    }
    else { // non-printable values are replaced by a dot
        strcat(ascii_str,".");
    }
}

void print_packet(const u_char* packet, unsigned X) {

    printf("0x%.3d0: ",X);
    char ascii_str[16] = "";
    unsigned Y = (X != 0) ? X*16 : 0; // print 0-15, 16-32, 32 - 64 ... B
    for (unsigned i = Y; i < 16*(X+1); i++) {
        if (no_bytes != 0) {
            printf("%02X ", (unsigned int) packet[i]);
            convert_ascii(ascii_str, (unsigned int) packet[i]);
            no_bytes--;
        }
        else //if all packet has been printed, print spaces
            printf("   ");
    }
    printf("%s\n",ascii_str);
}

void process_packet(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet)
{

    no_bytes = pkthdr->len; // number of bytes of packet

    // convert time
    struct tm* lt = localtime(&pkthdr->ts.tv_sec);
    char time_[MAX_TIME];
    strftime(time_, MAX_TIME-1, "%X", lt);

    //	IP header -> X + SIZE_ETHERNET
    struct iphdr *iph = (struct iphdr*)(packet + ETHERNET_SIZE);

    // get port numbers
    unsigned short *src_port = (unsigned short *) malloc(sizeof(unsigned short));
    unsigned short *dst_port = (unsigned short *) malloc(sizeof(unsigned short));
    check_protocol(packet,iph, src_port, dst_port);

    // check ip header
    unsigned size_ip = iph->ihl*4;
    if (size_ip < MAX_IP_SIZE) {
        printf("   * Invalid IP header length: %u bytes\n", size_ip);
        return;
    }
    // get source and destination ip address
    char* src = (char*) malloc(sizeof(char)*size_ip);
    char *dst = (char*) malloc(sizeof(char)*size_ip);
    get_src_dst_addr(src,dst,iph);

    // print header
    printf("%s.%ld %s : %u > %s : %u\n\n",time_,pkthdr->ts.tv_usec,src,*src_port,dst,*dst_port);

    // free allocated memory
    free(src); free(dst);
    free(src_port); free(dst_port);

    unsigned size_of_packet = pkthdr->len/HEX;
    for (unsigned i = 0; i < size_of_packet+1; i++) {
        print_packet(packet,i);
    }
    printf("\n");

}
/** note code bordered with block comment is under Copyright:
    ****************************************************************************
    *  This document is Copyright 2002 Tim Carstens. All rights reserved. Redistribution and use, with or without modification, are permitted provided that the following conditions are met:
    *  Redistribution must retain the above copyright notice and this list of conditions.
    *  The name of Tim Carstens may not be used to endorse or promote products derived from this document without specific prior written permission.
    *  https://www.tcpdump.org/pcap.html
    ****************************************************************************/
int sniff(char *interface, int no_packets, int port, char *protocol){

    /****************************************************************************
     *  https://www.tcpdump.org/pcap.html
     ****************************************************************************/
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* descr;
    struct bpf_program fp;        /* to hold compiled program */
    bpf_u_int32 pMask;            /* subnet mask */
    bpf_u_int32 pNet;             /* ip address*/
    char port_s[10]; //port string
    snprintf(port_s, 10,"%d", port); // convert port number to string
    pcap_lookupnet(interface, &pNet, &pMask, errbuf);

    descr = pcap_open_live(interface, BUFSIZ, 0,-1, errbuf);
    if(descr == NULL)
    {
        printf("pcap_open_live() failed due to [%s]\n", errbuf);
        return -1;
    }
    /******************************************************************************/

    char filter[100] = "";
    if (strcmp(protocol, "none") || (port != -1)) {
        if (strcmp(protocol, "none")) { // add tcp/udp filter
            strcat(filter, protocol);
        }
        if (port != -1) { //concat port filter
            if (strncmp(filter,"",1)) // add space
                strcat(filter," ");
            strcat(filter, "port ");
            strcat(filter,port_s);
        }
    }
    /****************************************************************************
    *  https://www.tcpdump.org/pcap.html
    ****************************************************************************/
    // apply filter
    if (strncmp(filter,"",1)) {
        if(pcap_compile(descr, &fp,filter, 0, pNet) == -1)
        {
            printf("\npcap_compile() failed\n");
            return -1;
        }
        if(pcap_setfilter(descr, &fp) == -1)
        {
            printf("\npcap_setfilter() failed\n");
            exit(1);
        }
    }
    /**************************************************************************/
    // For every packet received, call the process_packet function
    pcap_loop(descr,no_packets, process_packet, NULL);
    pcap_close(descr); //close session
    return 0;
}
