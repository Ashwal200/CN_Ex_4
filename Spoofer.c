#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include "header.h"

#define PACKET_LEN 1500
#define DST_IP "1.1.1.1"


//  Given an IP packet, send it out using a raw socket.

void send_raw_ip_packet(struct ipheader* ip)
{
    struct sockaddr_in dest_info;
    int enable = 1;

    // Step 1: Create a raw network socket.
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    // Step 2: Set socket option.
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL,&enable, sizeof(enable));

    // Step 3: Provide needed information about destination
    dest_info.sin_family = AF_INET;
    dest_info.sin_addr = ip->iph_destip;

    // Step 4: Send the packet out.
    printf("Sending spoofd IP packet...");
    if (sendto(sock, ip, ntohs(ip->iph_len), 0,(struct sockaddr *)&dest_info, sizeof(dest_info)) < 0){
        fprintf(stderr, "sendto() failed with error: %d\n", errno);
    }
    else{
        printf("\n..........................................\n");
        printf("IP source: %s\n", inet_ntoa(ip->iph_sourceip));
        printf("IP dest: %s\n", inet_ntoa(ip->iph_destip));
        printf("\n..........................................\n");
    }
    close(sock);
}


//  Spoof an ICMP echo request

int main(int argc, char *argv[]){
    //check the IP
    if (argc == 1) {
        argv[1] = "8.8.8.8";
    }

    char buffer[PACKET_LEN];
    memset(buffer, 0, PACKET_LEN);

    // Fill in the ICMP header
    struct icmpheader *icmp = (struct icmpheader *) (buffer + sizeof(struct ipheader));

    //ICMP type 8 for request and 0 for replay
    icmp->icmp_type = 8;

    // Calculate checksum
    icmp->icmp_chksum = 0;
    icmp-> icmp_chksum = calculate_checksum((unsigned short *)icmp, sizeof(struct icmpheader));

    //Fill in the IP header
    struct ipheader *ip = (struct ipheader *) buffer;
    ip->iph_ver = 4;
    ip->iph_ihl = 5;
    ip->iph_tos = 16;
    ip->iph_ttl = 128;
    ip->iph_sourceip.s_addr = inet_addr(argv[1]);
    ip->iph_destip.s_addr = inet_addr(DST_IP);
    ip->iph_protocol = IPPROTO_ICMP;
    ip->iph_len = htons(sizeof(struct ipheader) + sizeof(struct icmpheader));

    //send the spoofed packet
    send_raw_ip_packet(ip);

    return 0;
}


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


