#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <regex.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <time.h>

#define MAX_HOST_LEN 256
#define MAX_LINE_LEN 512
#define HASH_TABLE_SIZE 1000003  // large prime number for hashing

// hashtable
char** blocked_sites = NULL;

unsigned long hash(const char* str) {
    unsigned long hash = 5381;
    int c;
    while ((c = *str++))
        hash = ((hash << 5) + hash) + c;
    return hash % HASH_TABLE_SIZE;
}

void insertBlockHost(const char* host) {
    unsigned long h = hash(host);
    while (blocked_sites[h]) {
        if (strcmp(blocked_sites[h], host) == 0) return; // 이미 존재
        h = (h + 1) % HASH_TABLE_SIZE;
    }
    blocked_sites[h] = strdup(host);
}

int isBlockedHost(const char* host) {
    unsigned long h = hash(host);
    while (blocked_sites[h]) {
        if (strcmp(blocked_sites[h], host) == 0) return 1;
        h = (h + 1) % HASH_TABLE_SIZE;
    }
    return 0;
}

void loadBlockList(const char* filename) {
    FILE* fp = fopen(filename, "r");
    if (!fp) {
        perror("fopen");
        exit(1);
    }

    blocked_sites = calloc(HASH_TABLE_SIZE, sizeof(char*));
    if (!blocked_sites) {
        perror("calloc");
        exit(1);
    }

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    char line[MAX_LINE_LEN];
    while (fgets(line, sizeof(line), fp)) {
        char* comma = strchr(line, ',');
        if (!comma) continue;
        char* site = comma + 1;
        site[strcspn(site, "\r\n")] = 0;
        insertBlockHost(site);
    }

    clock_gettime(CLOCK_MONOTONIC, &end);
    double t = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
    printf("[*] Block list loaded in %.6f seconds\n", t);
    fclose(fp);
}

int extractHostRegex(const char* payload, int payload_len, char* out_host, size_t max_len) {
    regex_t regex;
    regmatch_t matches[2];
    const char* pattern = "Host: \([^\r\n]+\)";
    char* payload_str = strndup(payload, payload_len);

    if (regcomp(&regex, pattern, REG_EXTENDED)) {
        fprintf(stderr, "Could not compile regex\n");
        free(payload_str);
        return 0;
    }

    int ret = 0;
    if (regexec(&regex, payload_str, 2, matches, 0) == 0) {
        int start = matches[1].rm_so;
        int end = matches[1].rm_eo;
        int len = end - start;
        if (len > 0 && len < max_len) {
            strncpy(out_host, payload_str + start, len);
            out_host[len] = '\0';
            ret = 1;
        }
    }

    regfree(&regex);
    free(payload_str);
    return ret;
}
int checkHttpHost(unsigned char *data, int size) {
    struct iphdr *ip = (struct iphdr *)data;
    if (ip->protocol != IPPROTO_TCP) return 0;

    int ip_hdr_len = ip->ihl * 4;
    struct tcphdr *tcp = (struct tcphdr *)(data + ip_hdr_len);
    int tcp_hdr_len = tcp->doff * 4;

    unsigned char *payload = data + ip_hdr_len + tcp_hdr_len;
    int payload_len = size - ip_hdr_len - tcp_hdr_len;
    if (payload_len <= 0) return 0;

    if (memcmp(payload, "GET ", 4) != 0 && memcmp(payload, "POST", 4) != 0)
        return 0;

    char host[MAX_HOST_LEN] = {0};
    if (extractHostRegex((char *)payload, payload_len, host, sizeof(host))) {
        printf("[+] HTTP Host: %s\n", host);
        if (isBlockedHost(host)) {
            printf("[!] BLOCKED: %s\n", host);
            return 1;
        }
    }
    return 0;
}

static u_int32_t processPacket(struct nfq_data *tb, int *should_block) {
    u_int32_t id = 0;
    unsigned char *data;
    int ret;

    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(tb);
    if (ph) id = ntohl(ph->packet_id);

    ret = nfq_get_payload(tb, &data);
    if (ret >= 0 && checkHttpHost(data, ret)) {
        *should_block = 1;
    }

    return id;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data) {
    int drop = 0;
    u_int32_t id = processPacket(nfa, &drop);
    return nfq_set_verdict(qh, id, drop ? NF_DROP : NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <site list csv>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    loadBlockList(argv[1]);

    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    int fd, rv;
    char buf[4096] __attribute__((aligned));

    h = nfq_open();
    if (!h) {
        perror("nfq_open");
        exit(EXIT_FAILURE);
    }

    if (nfq_unbind_pf(h, AF_INET) < 0) {
        perror("nfq_unbind_pf");
        exit(EXIT_FAILURE);
    }

    if (nfq_bind_pf(h, AF_INET) < 0) {
        perror("nfq_bind_pf");
        exit(EXIT_FAILURE);
    }

    qh = nfq_create_queue(h, 0, &cb, NULL);
    if (!qh) {
        perror("nfq_create_queue");
        exit(EXIT_FAILURE);
    }

    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        perror("nfq_set_mode");
        exit(EXIT_FAILURE);
    }

    fd = nfq_fd(h);
    while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) {
        nfq_handle_packet(h, buf, rv);
    }

    nfq_destroy_queue(qh);
    nfq_close(h);
    return 0;
}
