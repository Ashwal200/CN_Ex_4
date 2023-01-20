#ifndef CN_EX4_MY_HEADER_H
#define CN_EX4_MY_HEADER_H



// Ethernet header
struct hdr_ethernet {
	u_char ether_dhost[6];
	u_char ether_shost[6];
	u_short ether_type;
};

// IP header
struct hdr_ip {
    u_char ip_hdr_len:4,
    ip_version:4;       /* version << 4 | header length >> 2 */
    u_char tos;		        /* type of service */
    u_short tot_len;		/* total length */
    u_short ip_id;		        /* identification */
    u_short ip_off;		/* fragment offset field */
#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* don't fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
    u_char ip_ttl;		/* time to live */
    u_char ip_protocol;		/* protocol */
    u_short check;		/* checksum */
    struct in_addr ip_src, ip_dst; /* source and dest address */
};


/* ICMP Header  */
struct hdr_icmp {
    unsigned char icmp_type; // ICMP message type
    unsigned char icmp_code; // Error code
    unsigned short int icmp_chksum; //Checksum for ICMP Header and data
    unsigned short int icmp_my_id;     //Used for identifying request
    unsigned short int icmp_my_seq;    //Sequence number
};

// TCP header
typedef u_int tcp_seq;

struct hdr_tcp {
	u_short source_port;
	u_short destination_port;
	tcp_seq seq_num;
	tcp_seq ack_num;
	u_char data_off;
#define TH_OFF(th)	(((th)->data_off & 0xf0) > 4)
	u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short th_win;
	u_short th_sum;
	u_short th_urp;
};

/* app header*/
struct hdr_info {
	
  uint32_t timestamp;
  uint16_t total_length;
  union
  {
    uint16_t reserved : 3;
    uint16_t cache_flag : 1;
    uint16_t steps_flag : 1;
    uint16_t type_flag : 1;
    uint16_t status_code : 10;
    uint16_t flags;
  };

  uint16_t cache_control;
  uint16_t padding;
};

/* Psuedo TCP header */
struct pseudo_tcp
{
    unsigned saddr, daddr;
    unsigned char mbz;
    unsigned char ptcl;
    unsigned short tcpl;
    struct hdr_tcp tcp;
    char payload[1500];
};


#endif //CN_Ex4_HEADER_H