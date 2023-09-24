#include <stdio.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include "network_headers.h" // 네트워크 헤더 파일 포함

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct ethheader *eth = (struct ethheader *)packet;

    // Check if it's an IP packet (Ethernet type 0x0800 corresponds to IP)
        if (ntohs(eth->ether_type) == ETHERTYPE_IP) { // Check if it's an IP packet
        struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));

        if (ip->iph_protocol == IPPROTO_TCP) { // Check if it's a TCP packet
            struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + ip->iph_ihl * 4);

            printf("Ethernet Header:\n");
            printf("  Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                   eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
                   eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
            printf("  Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                   eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
                   eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

            printf("IP Header:\n");
            printf("  Source IP: %s\n", inet_ntoa(ip->iph_sourceip));
            printf("  Destination IP: %s\n", inet_ntoa(ip->iph_destip));

            printf("TCP Header:\n");
            printf("  Source Port: %d\n", ntohs(tcp->tcp_sport));
            printf("  Destination Port: %d\n", ntohs(tcp->tcp_dport));

            // 여기에 추가적인 TCP 헤더 정보를 출력하거나 원하는 작업을 수행할 수 있습니다.
        }
    }
}

int main() {
    char *dev = "ens33"; // 네트워크 인터페이스 이름을 설정하세요
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    // 네트워크 인터페이스를 열고 패킷 캡처를 시작합니다
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return 1;
    }

    // 패킷 캡처를 위한 루프를 시작하고 패킷을 packet_handler 함수로 전달합니다
    pcap_loop(handle, 0, packet_handler, NULL);

    // 패킷 캡처 핸들을 닫습니다
    pcap_close(handle);

    return 0;
}

