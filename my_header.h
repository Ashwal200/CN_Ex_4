
#define ETHER_ADDR_LEN	6

// Ethernet header
struct hdr_ethernet {
	u_char ether_dhost[ETHER_ADDR_LEN];
	u_char ether_shost[ETHER_ADDR_LEN];
	u_short ether_type;
};

// IP header
struct hdr_ip {
	u_char ip_vhl;
	u_char ip_tos;
	u_short ip_len;
	u_short ip_id;
	u_short ip_off;
#define IP_RF 0x8000
#define IP_DF 0x4000
#define IP_MF 0x2000
#define IP_OFFMASK 0x1fff
	u_char ip_ttl;
	u_char ip_p;
	u_short ip_sum;
	struct in_addr ip_src, ip_dst;
};
#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

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