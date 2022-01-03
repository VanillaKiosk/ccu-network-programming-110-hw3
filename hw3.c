#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/ethernet.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#include <pcap.h>

void pcap_callback(u_char *arg, const struct pcap_pkthdr *header, const u_char *content);
void ethernet_callback(const u_char *packet);
void ip_callback(const u_char *bin);
void tcp_callback(const u_char *bin);
void udp_callback(const u_char *bin);

int main(int argc, char **argv) {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct tm* tm;
    char tsfm[64];
    struct pcap_pkthdr header;
    const u_char *packet;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <pcap file>\n", argv[0]);
        exit(1);
    }

    if ((handle = pcap_open_offline(argv[1], errbuf)) == NULL) {
        fprintf(stderr, "Error: %s\n", errbuf);
        exit(1);
    }

    size_t no = 0;
    fprintf(stdout, "\n\n");
    while ((packet = pcap_next(handle, &header)) != NULL) {
        printf("No. %u\n", ++no);
        pcap_callback(NULL, &header, packet);
    }

    pcap_close(handle);
    
    return 0;
}

void pcap_callback(u_char *arg, const struct pcap_pkthdr *header, const u_char *packet) {
    static int d = 0;
    struct tm *ltime;
    char timestr[64];
    time_t local_tv_sec;

    local_tv_sec = header->ts.tv_sec;
    ltime = localtime(&local_tv_sec);
    strftime(timestr, sizeof(timestr), "%Y-%m-%d %H:%M:%S", ltime);

    printf("\tTime: %s.%.6d\n\n", timestr, header->ts.tv_usec);
    //printf("\tLength: %d bytes\n", header->len);
    //printf("\tCapture length: %d bytes\n", header->caplen);
    
    ethernet_callback(packet);

    printf("\n");

    return;
}

void ethernet_callback(const u_char *packet) {
    struct ether_header *ethernet;
    
    ethernet = (struct ether_header*)(packet);

    uint8_t *s = ethernet->ether_shost;
    uint8_t *d = ethernet->ether_dhost;
    printf("\tSrc MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", s[0], s[1], s[2], s[3], s[4], s[5]);
    printf("\tDst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", d[0], d[1], d[2], d[3], d[4], d[5]);

    switch(ntohs(ethernet->ether_type)) {
        case ETHERTYPE_PUP:
            printf("\tEthertype: Xerox PUP\n");
            break;
        case ETHERTYPE_SPRITE:
            printf("\tEthertype: Sprite\n");
            break;
        case ETHERTYPE_IP:
            printf("\tEthertype: IP\n");
            ip_callback(packet + sizeof(struct ether_header));
            break;
        case ETHERTYPE_ARP:
            printf("\tEthertype: ARP\n");
            break;
        case ETHERTYPE_REVARP:
            printf("\tEthertype: Reverse ARP\n");
            break;
        case ETHERTYPE_AT:
            printf("\tEthertype: AppleTalk protocol\n");
            break;
        case ETHERTYPE_AARP:
            printf("\tEthertype: AppleTalk ARP\n");
            break;
        case ETHERTYPE_VLAN:
            printf("\tEthertype: IEEE 802.1Q VLAN tagging\n");
            break;
        case ETHERTYPE_IPX:
            printf("\tEthertype: IPX\n");
            break;
        case ETHERTYPE_IPV6:
            printf("\tEthertype: IPv6\n");
            break;
        case ETHERTYPE_LOOPBACK:
            printf("\tEthertype: Loopback\n");
            break;
        default:
            printf("\tEthertype: unknown\n");
            break;
    }

    return;
}

void ip_callback(const u_char *bin) {
    struct ip *ip;
    
    ip = (struct ip*)(bin);

    unsigned int hdr_length = (ip->ip_hl << 2);

    if (hdr_length < 20) {
        printf("\t\t* Invalid IP header length: %u bytes\n", hdr_length);
        return;
    }

    printf("\t\tSrc IP: %s\n", inet_ntoa(ip->ip_src));
	printf("\t\tDst IP: %s\n", inet_ntoa(ip->ip_dst));

    switch(ip->ip_p) {
        case IPPROTO_TCP:
            printf("\t\tIP Protocol: TCP\n");
            tcp_callback(bin + hdr_length);
            break;
        case IPPROTO_UDP:
            printf("\t\tIP Protocol: UDP\n");
            udp_callback(bin + hdr_length);
            break;
        case IPPROTO_ICMP:
            printf("\t\tIP Protocol: ICMP\n");
            break;
        default:
            printf("\t\tIP Protocol: unknown\n");
            break;
    }

    return;
}

void tcp_callback(const u_char *bin) {
    struct tcphdr *tcp;
    
    tcp = (struct tcphdr*)(bin);

    unsigned int hdr_length = (tcp->th_off << 2);

    if (hdr_length < 20) {
        printf("\t\t\t* Invalid TCP header length: %u bytes\n", hdr_length);
        return;
    }

    printf("\t\t\tSrc Port: %u\n", ntohs(tcp->th_sport));
	printf("\t\t\tDst Port: %u\n", ntohs(tcp->th_dport));

    return;
}

void udp_callback(const u_char *bin) {
    struct udphdr *udp;
    
    udp = (struct udphdr*)(bin);

    printf("\t\t\tSrc Port: %u\n", ntohs(udp->uh_sport));
	printf("\t\t\tDst Port: %u\n", ntohs(udp->uh_dport));

    return;
}

