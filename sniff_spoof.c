#include <pcap.h>
#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <linux/tcp.h>
#include <string.h>
#include <errno.h>
#include <netinet/ip_icmp.h>
#include "my_header.h"


unsigned short calculate_checksum(unsigned short *buf, int length) {
    int nleft = length;
    int sum = 0;
    unsigned short *w = buf;
    unsigned short answer = 0;

    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }

    if (nleft == 1) {
        *((unsigned char *) &answer) = *((unsigned char *) w);
        sum += answer;
    }

    // add back carry-outs from top 16 bits to low 16 bits
    sum = (sum >> 16) + (sum & 0xffff); // add hi 16 to low 16
    sum += (sum >> 16);                 // add carry
    answer = ~sum;                      // truncate to 16 bits

    return answer;
}

// //  Given an IP packet, send it out using a raw socket.

void send_echo_reply(struct hdr_ip *ip) {
    printf("Build Echo reply packet...\n");
    struct sockaddr_in dest_info;
    int enable = 1;

    // Step 1: create a raw network socket
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0)
        printf("Error with the socket.");
    // Step 2: set socket option
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable));

    // Step 3: Provide needed info about destination
    dest_info.sin_family = AF_INET;
    dest_info.sin_addr = ip->ip_dst;

    // Step 4: send the packet out
    printf("\nSending ECHO reply packet");

    if (sendto(sock, ip, ntohs(ip->tot_len), 0, (struct sockaddr *) &dest_info, sizeof(dest_info)) < 0) {
        fprintf(stderr, "sendto() failed with error: %d", errno);
        exit(1);
    } else {

        printf("\n------------------------------------------\n");

        printf("\t IP source: %s\n", inet_ntoa(ip->ip_src));

        printf("\t IP dest: %s\n", inet_ntoa(ip->ip_dst));

        printf("\n------------------------------------------\n");

    }
    close(sock);
}


// //  Spoof an ICMP echo request

void build_echo_reply(struct hdr_ip *ip) {
    int ip_header_len = ip->ip_hdr_len * 4;
    const char buffer[1500];

    //Make copy from the sniffed packet
    memset((char *) buffer, 0, 1500);
    memcpy((char *) buffer, ip, ntohs(ip->tot_len));

    // Fill in the ICMP header
    struct hdr_ip *build_ip = (struct hdr_ip *) buffer;
    struct hdr_icmp *build_icmp = (struct hdr_icmp *) (buffer + ip_header_len);

    //ICMP type 8 for request and 0 for replay
    build_icmp->icmp_type = 0;

    // Calculate checksum
    build_icmp->icmp_chksum = 0;
    build_icmp->icmp_chksum = calculate_checksum((unsigned short *) build_icmp, sizeof(struct hdr_icmp));

    //Swap source and destination for echo reply
    build_ip->ip_src = ip->ip_dst;
    build_ip->ip_dst = ip->ip_src;

    //Fill in the IP header
    build_ip->ip_version = 4;
    build_ip->ip_hdr_len = 5;
    build_ip->tos = 16;
    build_ip->ip_ttl = 128;
    build_ip->ip_protocol = IPPROTO_ICMP;
    build_ip->tot_len = htons(sizeof(struct hdr_ip) + sizeof(struct hdr_icmp));

    send_echo_reply(build_ip);
}


void catch_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {

    struct hdr_ethernet *eth = (struct hdr_ethernet *) packet;
    //Get the IP Header part of this packet
    struct hdr_ip *ip_check = (struct hdr_ip *) (packet + sizeof(struct hdr_ethernet));
    struct hdr_icmp *icmp = (struct hdr_icmp *) (packet + sizeof(struct hdr_ethernet) + sizeof(struct hdr_ip));
    printf("\nICMP packet!");
    printf("\n\n");
    printf("IP source: %s\n", inet_ntoa(ip_check->ip_src));
    printf("IP dest: %s\n", inet_ntoa(ip_check->ip_dst));
    printf("\n\n");
    if (icmp->icmp_type == ICMP_HOST_UNREACH || icmp->icmp_type == ICMP_HOST_UNKNOWN) {
        printf("###################   UNREACHABLE  ##################\n");
        build_echo_reply(ip_check);
    }
    else if (icmp->icmp_type == ICMP_ECHO){
        printf("ping request\n");
        build_echo_reply(ip_check);
    }
}
    int main() {
        pcap_t *handle;
        char errbuf[PCAP_ERRBUF_SIZE];
        struct bpf_program fp;

        char filter[] = "icmp[icmptype] = 8";

        bpf_u_int32 net;

        // Step 1: Open live pcap session on NIC with name eth3
        handle = pcap_open_live("br-fb03b7cf35f3", BUFSIZ, 1, 1000, errbuf);

        // Step 2: Compile filter_exp into BPF psuedo-code
        pcap_compile(handle, &fp, filter, 0, net);
        pcap_setfilter(handle, &fp);

        printf("\nStart sniffing packets, searching for ICMP packets only...\n");

        // Step 3: Capture packets
        pcap_loop(handle, -1, catch_packet, NULL);

        pcap_close(handle);   //Close the handle
        return 0;

    }
