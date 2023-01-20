#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <netinet/in.h>
#include "my_header.h"

#define IP "1.10.10.10"

unsigned short calculate_checksum(unsigned short *buf, int length);

//  Given an IP packet, send it out using a raw socket.

void send_icmp_packet(struct hdr_ip* ip)
{
    struct sockaddr_in dest_info;
    int enable;

    // Step 1: Create a raw network socket.
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    // Step 2: Set socket option.
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL,&enable, sizeof(enable));

    // Step 3: Provide needed information about destination
    dest_info.sin_family = AF_INET;
    dest_info.sin_addr = ip->ip_dst;


    // Step 4: Send the packet out.
    printf("Sending spoofd IP packet...");
    sendto(sock, ip, ntohs(ip->tot_len), 0,(struct sockaddr *)&dest_info, sizeof(dest_info));

    printf("\n\n");
    printf("IP source: %s\n", inet_ntoa(ip->ip_src));
    printf("IP dest: %s\n", inet_ntoa(ip->ip_dst));
    printf("\n\n");

    close(sock);
}

int check_ip(char *ip){
    struct sockaddr_in sock_in;
    int check = inet_pton(AF_INET , ip , &(sock_in.sin_addr));
    return check != 0;
}

//  Spoof an ICMP echo request

int main(int argc, char *argv[]){
    //check the IP
    if (argc == 1) {
        argv[1] = "8.8.8.8";
    }

    if (!check_ip(argv[1])){
        printf(" Sorry but this is not a valid ip please try again. \n");
        exit(1);
    }

    char buffer[1500];
    memset(buffer, 0, 1500);

    // Fill in the ICMP header
    struct hdr_icmp *icmp = (struct hdr_icmp *) (buffer + sizeof(struct hdr_ip));

    //ICMP type 8 for request and 0 for replay
    icmp->icmp_type = 8;

    // Calculate checksum
    icmp->icmp_chksum = 0;
    icmp-> icmp_chksum = calculate_checksum((unsigned short *)icmp, sizeof(struct hdr_icmp));

    //Fill in the IP header
    struct hdr_ip *ip = (struct hdr_ip *) buffer;
    ip->ip_version = 4;
    ip->ip_hdr_len = 5;
    ip->ip_ttl = 20;
    ip->ip_src.s_addr = inet_addr(argv[1]);
    ip->ip_dst.s_addr = inet_addr("10.10.10.10");
    ip->ip_protocol = IPPROTO_ICMP;
    ip->tot_len = htons(sizeof(struct hdr_ip) + sizeof(struct hdr_icmp));


    //send the spoofed packet
    send_icmp_packet(ip);

    return 0;
}


unsigned short calculate_checksum(unsigned short *buf, int length)
{
    unsigned short *w = buf;
    int nleft = length;
    int sum = 0;
    unsigned short temp=0;

    /*
     * The algorithm uses a 32 bit accumulator (sum), adds
     * sequential 16 bit words to it, and at the end, folds back all
     * the carry bits from the top 16 bits into the lower 16 bits.
     */
    while (nleft > 1)  {
        sum += *w++;
        nleft -= 2;
    }

    /* treat the odd byte at the end, if any */
    if (nleft == 1) {
        *(u_char *)(&temp) = *(u_char *)w ;
        sum += temp;
    }

    /* add back carry outs from top 16 bits to low 16 bits */
    sum = (sum >> 16) + (sum & 0xffff);  // add hi 16 to low 16
    sum += (sum >> 16);                  // add carry
    return (unsigned short)(~sum);
}


