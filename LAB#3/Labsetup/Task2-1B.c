#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/ether.h>

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ether_header *eth_header;
    struct ip *ip_header;

    eth_header = (struct ether_header *) packet;
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        ip_header = (struct ip *)(packet + sizeof(struct ether_header));
        printf("Source IP: %s\n", inet_ntoa(ip_header->ip_src));
        printf("Dest IP: %s\n", inet_ntoa(ip_header->ip_dst));
    }
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    //char filter_exp[] = "icmp and host 127.0.0.1";
    char filter_exp[] = "tcp dst portrange 10-100"; //Comment this back in when you want to test Part 2 of 2-1B
    bpf_u_int32 net;

    handle = pcap_open_live("lo", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open device enp0s3: %s\n", errbuf);
        return 2;
    }

    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Could not parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }
    if (pcap_setfilter(handle, &fp) != 0) {
        pcap_perror(handle, "Error:");
        exit(EXIT_FAILURE);
    }

    pcap_loop(handle, 0, got_packet, NULL);
    pcap_close(handle);
    return 0;
}

