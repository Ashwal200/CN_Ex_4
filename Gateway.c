#include<stdio.h>	//For standard things
#include<stdlib.h>	//malloc
#include<string.h>	//memset

#include<netinet/ip.h>	//Provides declarations for ip header
#include<sys/socket.h>


#include <errno.h>
#include <arpa/inet.h>

#define PORT  50000
#define PORT_1  50001



void send_udp_packet(unsigned char * , int , char *ip);




int sock_any , sock_ip;

struct sockaddr_in lst,sender;

int main(int argc , char *argv[])
{

    if (argc < 2)
    {
        printf("There is no IP input.\n")
        exit(1);
    }
    


    // Create socket
    sock_ip = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock_ip < 0) {
        perror("Error creating socket");
        return 1;
    }


    int lst_size , data_size;

    struct in_addr in;

    unsigned char *buffer = (unsigned char *)malloc(65536);



    printf("Starting the gateway process..\n");
    //Create a raw socket that shall sniff
    sock_any = socket(AF_INET , SOCK_DGRAM , 0);
    if(sock_any < 0)
    {
        printf("Socket Error\n");
        return 1;
    }

        lst.sin_port = htons(PORT);
        lst.sin_addr.s_addr = INADDR_ANY;
        lst.sin_family = AF_INET;
        lst_size = sizeof lst;

        if (bind(sock_any, (struct sockaddr *) &lst, lst_size) < 0) {
        perror("Error binding socket to IP and port");
        return 1;
    }
        int counter = 0;
    while(1)
    {

        printf("Listening to get UDP packets\n");
        //Receive a packet
        data_size = recvfrom(sock_any , buffer , 65536 , 0 , NULL , 0);
        if(data_size <0 )
        {
            printf("Recvfrom error , failed to get packets\n");
            return 1;
        }
        printf("\n\nRound number %d\n\n   Ready... \n\n   Fight !\n\n" , ++counter);

        double random_number = ((float)random())/((float)RAND_MAX);
        if (random_number > 0.5)
        {
            //Now process the packet
            printf("The number is : %f ,you have lucky today!\n" , random_number);
            send_udp_packet(buffer , data_size , argv[1]);
            printf("Transfer the data to: %s\n" , argv[1]);
        }
        else{
            printf("The number is : %f ,you have bad luck today maybe next time!\n" , random_number);
        }

    }
    close(sock_any);
    close(sock_ip);
    
    printf("Finished");
    return 0;
}





void send_udp_packet(unsigned char *packet, int size , char *ip)
{


    printf("\n\n*******UDP Packet******\n");

    // Set the destination address
    memset(&sender, 0, sizeof(sender));
    sender.sin_family = AF_INET;
    sender.sin_port = htons(PORT_1);
    sender.sin_addr.s_addr = inet_addr(ip);


    if(sendto(sock_ip, packet, size , 0, (struct sockaddr *) &sender, sizeof(sender)) < 0){
        perror("Error with sendto() the packet\n");

    }
    printf("Succeed with send the packet!\n");
    return;
}