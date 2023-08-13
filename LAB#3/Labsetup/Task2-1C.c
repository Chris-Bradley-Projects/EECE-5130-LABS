#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <ctype.h>
#include <string.h>

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ip *ip_packet = (struct ip *)(packet + 14); // Skip Ethernet header
    struct tcphdr *tcp_packet = (struct tcphdr *)(packet + 14 + (ip_packet->ip_hl << 2)); // Skip IP header
    u_char *data = (u_char *)(packet + 14 + (ip_packet->ip_hl << 2) + (tcp_packet->doff << 2)); // Point to TCP data

    int data_length = ntohs(ip_packet->ip_len) - (ip_packet->ip_hl << 2) - (tcp_packet->doff << 2);

    char buffer[data_length + 1];
    int index = 0;

    for(int i = 0; i < data_length; i++) {
        if(isprint(data[i])) { 
            buffer[index++] = data[i];
        }
    }
    buffer[index] = '\0'; // null terminate the string

    // Only print the buffer if it's not empty or just dots
    if (buffer[0] != '\0' && strcmp(buffer, ".") != 0 && strcmp(buffer, "..") != 0 && strcmp(buffer, "...") != 0) {
        printf("Data: %s\n", buffer);
    }
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp port 23"; 
    bpf_u_int32 net;

    handle = pcap_open_live("lo", BUFSIZ, 1, 1000, errbuf); 

    pcap_compile(handle, &fp, filter_exp, 0, net);
    if (pcap_setfilter(handle, &fp) != 0) {
        pcap_perror(handle, "Error:");
        exit(EXIT_FAILURE);
    }

    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle);
    return 0;
}



