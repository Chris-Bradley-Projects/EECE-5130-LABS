#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/ether.h>

void got_packet(u_char *args, const struct pcap_pkthdr *header,
        const u_char *packet) {

    struct ether_header *eth_header;
    struct ip *ip_header;

    // Get Ethernet header
    eth_header = (struct ether_header *) packet;

    // Check if it is an IP packet
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        // Get IP header
        ip_header = (struct ip *)(packet + sizeof(struct ether_header));
        printf("Source IP: %s\n", inet_ntoa(ip_header->ip_src));
        printf("Dest IP: %s\n", inet_ntoa(ip_header->ip_dst));
    }
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "ip"; // Change filter to capture all IP packets
    bpf_u_int32 net;

    // Step 1: Open live pcap session on NIC with name enp0s3
    handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf); 

    if (handle == NULL) {
        fprintf(stderr, "Could not open device enp0s3: %s\n", errbuf);
        return 2;
    }

    // Step 2: Compile filter_exp into BPF psuedo-code
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Could not parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }
    if (pcap_setfilter(handle, &fp) != 0) {
        pcap_perror(handle, "Error:");
        exit(EXIT_FAILURE);
    }

    // Step 3: Capture packets
    pcap_loop(handle, 0, got_packet, NULL); // 0 means infinite loop

    pcap_close(handle); // Close the handle
    return 0;
}
