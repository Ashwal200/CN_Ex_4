#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <linux/tcp.h>
#include <string.h>
#include <errno.h>
#include "header.h"


#define PACKET_LEN 1500

unsigned short calculate_checksum(unsigned short *buf, int length)
{
    int nleft = length;
    int sum = 0;
    unsigned short *w = buf;
    unsigned short answer = 0;

    while (nleft > 1)
    {
        sum += *w++;
        nleft -= 2;
    }

    if (nleft == 1)
    {
        *((unsigned char *)&answer) = *((unsigned char *)w);
        sum += answer;
    }

    // add back carry-outs from top 16 bits to low 16 bits
    sum = (sum >> 16) + (sum & 0xffff); // add hi 16 to low 16
    sum += (sum >> 16);                 // add carry
    answer = ~sum;                      // truncate to 16 bits

    return answer;
}

// //  Given an IP packet, send it out using a raw socket.

void send_raw_ip_packet(struct ipheader* ip) {
    struct sockaddr_in dest_info;
    int enable = 1;

    // Step 1: create a raw network socket
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    // Step 2: set socket option
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable));

    // Step 3: Provide needed info about destination
    dest_info.sin_family = AF_INET;
    dest_info.sin_addr = ip->iph_destip;

    // Step 4: send the packet out
    printf("\nSending spoofd IP packet...");

    if (sendto(sock, ip, ntohs(ip->iph_len), 0,(struct sockaddr *)&dest_info, sizeof(dest_info))<0){
        fprintf(stderr, "sendto() failed with error: %d", errno);

    }

    else{

        printf("\n..........................................\n");

        printf("\tIP source: %s\n", inet_ntoa(ip->iph_sourceip));

        printf("\tIP dest: %s\n", inet_ntoa(ip->iph_destip));

        printf("\n..........................................\n");

    }
    close(sock);
}


// //  Spoof an ICMP echo request

void echo_reply(struct ipheader* ip) {
    char buffer[PACKET_LEN];

    //Make copy from the sniffed packet
    memset(buffer, 0, PACKET_LEN);
    memcpy((char *)buffer, ip, ntohs(ip->iph_len));


    // Fill in the ICMP header
    struct ipheader* new_ip = (struct ipheader*) buffer;
    struct icmpheader* new_icmp = (struct icmpheader*) (buffer + sizeof(ip->iph_ihl * 4));

    //ICMP type 8 for request and 0 for replay
    new_icmp->icmp_type = 0;

    // Calculate checksum
    new_icmp->icmp_chksum = 0;
    new_icmp->icmp_chksum = calculate_checksum((unsigned short *)new_icmp, sizeof(struct icmpheader));

    //Fill in the IP header
    new_ip->iph_ver = 4;
    new_ip->iph_ihl = 5;
    new_ip->iph_tos = 16;
    new_ip->iph_ttl = 128;
    new_ip->iph_len = htons(sizeof(struct ipheader) + sizeof(struct icmpheader));

    //Swap source and destination for echo reply
    new_ip->iph_sourceip = ip->iph_destip;
    new_ip->iph_destip   = ip->iph_sourceip;
    send_raw_ip_packet(new_ip);
}



void got_packet(u_char *args, const struct pcap_pkthdr * header, const u_char *packet)
{
    struct ethheader eth = (struct ethheader) packet;

    if(ntohs(eth->ether_type) == 0x0800) { // 0x0800 = IP TYPE
        struct ipheader ip = (struct ipheader) (packet + sizeof(struct ethheader));
        printf("\nSniffing packet...");
        printf("\n---------------------------\n");
        printf("\tFrom: %s\n", inet_ntoa(ip->iph_sourceip));
        printf("\tTo: %s\n", inet_ntoa(ip->iph_destip));
        printf("\n---------------------------\n");
        // Determine protocol
        if(ip->iph_protocol == IPPROTO_ICMP) {
                printf("   Protocol: ICMP\n");
                echo_reply(ip);
        }
    }
}

int main()
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "ip proto icmp";
    bpf_u_int32 net;

    // Step 1: Open live pcap session on NIC with name enp0s3
    handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);

    // Step 2: Compile filter_exp into BPF psuedo-code
    pcap_compile(handle, &fp, filter_exp, 0, net);
    pcap_setfilter(handle, &fp);

    // Step 3: Capture packets
    pcap_loop(handle, -1, got_packet, NULL);


    pcap_close(handle);
    return 0;
}