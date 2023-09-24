#ifndef NETWORK_HEADERS_H
#define NETWORK_HEADERS_H

/* Ethernet header */
struct ethheader {
    u_char  ether_dhost[6];    /* destination host address */
    u_char  ether_shost[6];    /* source host address */
    u_short ether_type;        /* IP? ARP? RARP? etc */
};

/* IP Header */
struct ipheader {
    unsigned char      iph_ihl:4, // IP header length
                     iph_ver:4;   // IP version
    unsigned char      iph_tos;    // Type of service
    unsigned short int iph_len;    // IP Packet length (data + header)
    unsigned short int iph_ident;  // Identification
    unsigned short int iph_flag:3, // Fragmentation flags
                     iph_offset:13; // Flags offset
    unsigned char      iph_ttl;    // Time to Live
    unsigned char      iph_protocol; // Protocol type
    unsigned short int iph_chksum; // IP datagram checksum
    struct  in_addr    iph_sourceip; // Source IP address
    struct  in_addr    iph_destip;   // Destination IP address
};

/* TCP Header */
struct tcpheader {
    u_short tcp_sport;               // Source port
    u_short tcp_dport;               // Destination port
    u_int   tcp_seq;                 // Sequence number
    u_int   tcp_ack;                 // Acknowledgement number
    u_char  tcp_offx2;               // Data offset, rsvd
#define TH_OFF(th)      (((th)->tcp_offx2 & 0xf0) >> 4)
    u_char  tcp_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short tcp_win;                 // Window
    u_short tcp_sum;                 // Checksum
    u_short tcp_urp;                 // Urgent pointer
};

#endif // NETWORK_HEADERS_H
