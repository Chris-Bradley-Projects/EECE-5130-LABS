#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

void send_reply(const struct icmphdr *icmph, const struct ip *iph);
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    
    handle = pcap_open_live("lo", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open device lo: %s\n", errbuf);
        return 2;
    }

    // Filter ICMP echo requests
    struct bpf_program fp;
    char filter_exp[] = "icmp[icmptype] = icmp-echo";
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Could not parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Could not install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }

    pcap_loop(handle, 0, got_packet, NULL);
    pcap_close(handle);
    return 0;
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    const struct ether_header *ethernet = (struct ether_header *) packet;
    const struct ip *iph = (struct ip *)(packet + sizeof(struct ether_header));
    const struct icmphdr *icmph = (struct icmphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));

    send_reply(icmph, iph);
}

void send_reply(const struct icmphdr *icmph, const struct ip *iph) {
    int sd;
    struct sockaddr_in sin;
    char buffer[1024];

    struct ip *ip = (struct ip *) buffer;
    struct icmphdr *icmp = (struct icmphdr *)(buffer + sizeof(struct ip));

    sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if(sd < 0) {
        perror("socket() error");
        exit(-1);
    }
    sin.sin_family = AF_INET;
    sin.sin_addr = iph->ip_src;

    // Fill in IP header
    ip->ip_hl = 5;
    ip->ip_v = 4;
    ip->ip_tos = 0;
    ip->ip_len = sizeof(struct ip) + sizeof(struct icmphdr);
    ip->ip_id = 0;
    ip->ip_off = 0;
    ip->ip_ttl = 64;
    ip->ip_p = IPPROTO_ICMP;
    ip->ip_sum = 0;
    ip->ip_src = iph->ip_dst;
    ip->ip_dst = iph->ip_src;

    // Fill in ICMP header
    icmp->type = ICMP_ECHOREPLY;
    icmp->code = 0;
    icmp->un.echo.id = icmph->un.echo.id;
    icmp->un.echo.sequence = icmph->un.echo.sequence;
    icmp->checksum = 0; // Should be computed, but for simplicity omitted here

    sendto(sd, buffer, ip->ip_len, 0, (struct sockaddr *)&sin, sizeof(sin));
    close(sd);
}




