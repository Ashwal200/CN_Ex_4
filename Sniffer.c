#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <pcap.h>
#include <pcap/pcap.h>
#include <time.h>
#include <netinet/in.h>


#include<netinet/ip_icmp.h>	//Provides declarations for icmp header
#include<netinet/udp.h>	//Provides declarations for udp header
#include<netinet/tcp.h>	//Provides declarations for tcp header
#include<netinet/ip.h>

#include "my_header.h"

#define PCAP_ERROR -1
#define SIZE_ETHERNET 14


void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    int counter = 0;
    printf("TCP packet number %d\n" , ++counter);


    FILE *file;

    char name_of_ID[28] = "208573139_208647701.txt";
    // open the file in append mode
    file = fopen(name_of_ID, "a");
    if (file == NULL)
        printf("Error with open open the file.\n");

    const struct hdr_ethernet *ethernet = (struct hdr_ethernet*)(packet);

    const struct hdr_ip *ip = (struct hdr_ip*)(packet + SIZE_ETHERNET);

    u_int size_ip = IP_HL(ip)*4;

    const struct hdr_tcp *tcp = (struct hdr_tcp*)(packet + SIZE_ETHERNET + size_ip);

    u_int size_tcp = TH_OFF(tcp)*4;

    const struct hdr_info *info = (struct hdr_info *)(packet + SIZE_ETHERNET + size_ip + size_tcp);

    fprintf(file ,"\n****************** TCP Packet ******************\n");

    fprintf(file ,"\n---------------- IP Header  ------------------\n");
    fprintf(file ," - Source IP: %s\n",inet_ntoa(ip->ip_src));
    fprintf(file ," - Destination IP: %s\n",inet_ntoa(ip->ip_dst));

    fprintf(file ,"\n---------------- TCP Header  ------------------\n");
    fprintf(file ," » Source port: %d\n",ntohs(tcp->source_port));
    fprintf(file ," » Destination port: %d\n",ntohs(tcp->destination_port));
    fprintf(file ," » Sequence number: %d\n",ntohs(tcp->seq_num));
    fprintf(file ," » Time stamp: %u\n",ntohl(info->timestamp));
    fprintf(file ," » Total length: %u\n",ntohs(header->len));
    fprintf(file ," » Cache flage: %u\n",info->cache_flag);
    fprintf(file ," » Steps flage: %u\n",info->steps_flag);
    fprintf(file ," » Type flag: %u\n",info->type_flag);
    fprintf(file ," » Status code: %u\n",info->status_code);
    fprintf(file ," » Cache control: %u\n",info->cache_control);
    fprintf(file ,"                  -> DATA : ");
    uint8_t *data = (uint8_t *)malloc(sizeof(uint8_t) * header->len);
    if (!data)
    {
        return;
    }


    for (int i = 0; i < header->len; i++)
    {
        if (i%16 == 0){
            fprintf(file, "\n      ");
            fprintf(file, "%04X: ", i);
        }
        fprintf(file, "%02X ", (uint8_t)data[i]);
    }

    fprintf(file, "\n\n");

    fprintf(file , "\n************************************************************\n");

    fclose(file);


}


int main(){

    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "proto TCP and dst port 9999 or src port 9999 or dst port 9998 or src port 9998"; /* The filter expression */
    bpf_u_int32 netmask;
    bpf_u_int32 srcip;
    char nameDevice[] = "lo";


    pcap_lookupnet(nameDevice, &srcip, &netmask, errbuf);

    handle = pcap_open_live(nameDevice, BUFSIZ, 1, 1000, errbuf);
    if(handle==NULL) 
    {
        fprintf(stderr, "Couldn't open device %s: %s\n", nameDevice, errbuf);
        exit(1);
    }

    pcap_compile(handle, &fp, filter_exp, 0, srcip);

    pcap_setfilter(handle, &fp);

    pcap_loop(handle, -1, got_packet, NULL);                

    pcap_close(handle);
    return 0;
}