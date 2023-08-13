#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

// ICMP header structure
struct icmphdr {
    uint8_t type;        // ICMP packet type
    uint8_t code;        // Type sub code
    uint16_t checksum;
    uint16_t id;
    uint16_t seq;
};

// Checksum calculation function
unsigned short calculate_checksum(unsigned short *paddress, int len) {
    int nleft = len;
    int sum = 0;
    unsigned short *w = paddress;
    unsigned short answer = 0;

    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }

    if (nleft == 1) {
        *((unsigned char *)&answer) = *((unsigned char *)w);
        sum += answer;
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    answer = ~sum;
    return (answer);
}

int main() {
    struct iphdr *ip;
    struct icmphdr *icmp;
    char buffer[1500];

    memset(buffer, 0, 1500);

    // IP header
    ip = (struct iphdr *) buffer;
    ip->ihl = 5;
    ip->version = 4;
    ip->tos = 16; // Low delay
    ip->tot_len = sizeof(struct iphdr) + sizeof(struct icmphdr);
    ip->id = htons(54321);
    ip->ttl = 64; // hops
    ip->protocol = 1; // ICMP
    ip->saddr = inet_addr("10.0.2.4"); // spoofed source IP
    ip->daddr = inet_addr("10.0.2.4"); // destination
    ip->check = calculate_checksum((unsigned short *)buffer, ip->tot_len);

    // ICMP header
    icmp = (struct icmphdr *)(buffer + sizeof(struct iphdr));
    icmp->type = 8; // ICMP Echo Request type
    icmp->code = 0;
    icmp->checksum = 0;
    icmp->id = getpid();
    icmp->seq = 1;
    icmp->checksum = calculate_checksum((unsigned short *)icmp, sizeof(struct icmphdr));

    // Socket creation
    int sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sd < 0) {
        perror("socket() error");
        return -1;
    }

    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = 0;
    sin.sin_addr.s_addr = ip->daddr;

    if (sendto(sd, buffer, ip->tot_len, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        perror("sendto() error");
        close(sd);
        return -1;
    }
    printf("Spoofed packet sent\n");
    close(sd);
    return 0;
}




