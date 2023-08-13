#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

// ICMP header's checksum
unsigned short csum(unsigned short *buf, int len) {
    unsigned long sum;
    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;
    if (len == 1)
        sum += *(unsigned char *)buf;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return ~sum;
}

int main() {
    int sd;
    struct sockaddr_in sin;
    char buffer[1024];
    struct iphdr *ip = (struct iphdr *) buffer;
    struct icmphdr *icmp = (struct icmphdr *) (buffer + sizeof(struct iphdr));

    // Create raw socket
    sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if(sd < 0) {
        perror("socket() error");
        exit(-1);
    }

    // Socket configuration
    sin.sin_family = AF_INET;
    sin.sin_port = htons(80);
    sin.sin_addr.s_addr = inet_addr("1.2.3.4"); // Fake source IP

    // Zero out the buffer
    memset(buffer, 0, 1024);

    // IP Header
    ip->ihl = 5;
    ip->version = 4;
    ip->tos = 0;
    ip->tot_len = sizeof(struct iphdr) + sizeof(struct icmphdr);
    ip->id = htons(54321);
    ip->frag_off = 0;
    ip->ttl = 255;
    ip->protocol = IPPROTO_ICMP;
    ip->saddr = inet_addr("10.0.2.4"); // Your IP
    ip->daddr = sin.sin_addr.s_addr;
    ip->check = csum((unsigned short *)buffer, sizeof(struct iphdr) + sizeof(struct icmphdr));

    // ICMP Header
    icmp->type = ICMP_ECHO;
    icmp->code = 0;
    icmp->un.echo.sequence = rand();
    icmp->un.echo.id = rand();
    icmp->checksum = csum((unsigned short *)icmp, sizeof(struct icmphdr));

    // Send the packet
    if(sendto(sd, buffer, sizeof(struct iphdr) + sizeof(struct icmphdr), 0, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        perror("sendto() error");
        exit(-1);
    }

    printf("Spoofed packet sent\n");

    return 0;
}



