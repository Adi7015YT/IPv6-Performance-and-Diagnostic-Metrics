#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ip6.h>
#include <netdb.h>
#include <fcntl.h>
#include <time.h>
#include <net/if.h>
#include <sys/time.h>
#include <stdbool.h>

#pragma pack(push, 1)
struct ipv6_hdr {
    uint32_t vtf;          // Version (4), Traffic Class (8), Flow Label (20)
    uint16_t payload_len;  // Payload length (excluding IPv6 header)
    uint8_t  next_header;  // Next header (IPPROTO_DSTOPTS = 60)
    uint8_t  hop_limit;    // TTL
    uint8_t  src_addr[16]; // Source IPv6 address
    uint8_t  dst_addr[16]; // Destination IPv6 address
};

struct dest_opt_hdr {
    uint8_t next_header;   // Next header after this extension
    uint8_t hdr_ext_len;   // Header extension length (in 8-octet units)
    uint8_t options[14];   // PDM option + padding (14 bytes)
};

struct pdm_option {
    uint8_t  option_type;  // 0x0F (00001111)
    uint8_t  opt_len;      // 10 (length excluding type and length fields)
    uint8_t  scale_dtlr;   // Scale for Delta Time Last Received
    uint8_t  scale_dtls;   // Scale for Delta Time Last Sent
    uint16_t psntp;        // Packet Sequence Number This Packet
    uint16_t psnlr;        // Packet Sequence Number Last Received
    uint16_t deltatlr;     // Delta Time Last Received
    uint16_t deltatls;     // Delta Time Last Sent
} __attribute__((aligned(4)));

struct udp_hdr {
    uint16_t src_port;     // Source port
    uint16_t dst_port;     // Destination port (DNS = 53)
    uint16_t len;          // UDP header + payload length
    uint16_t checksum;     // Checksum (RFC 2460 pseudo-header)
};

struct dns_hdr {
    uint16_t trans_id;     // Transaction ID
    uint16_t flags;        // Flags (0x0100 for standard query)
    uint16_t questions;    // Number of questions (1)
    uint16_t answer_rrs;   // Answer RRs (0)
    uint16_t authority_rrs;// Authority RRs (0)
    uint16_t additional_rrs;// Additional RRs (0)
};
#pragma pack(pop)

struct flow_state {
    uint16_t current_psn;
    uint16_t last_received_psn;
    struct timespec last_send_time;
    struct timespec last_recv_time;
    int initialized;
};

uint16_t get_random_psn() {
    uint16_t psn;
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0 || read(fd, &psn, sizeof(psn)) != sizeof(psn)) {
        perror("Failed to generate PSN");
        exit(EXIT_FAILURE);
    }
    close(fd);
    return psn;
}

uint16_t compute_udp_checksum(
    const struct ipv6_hdr *ip6,
    const struct udp_hdr *udp,
    const uint8_t *payload,
    size_t payload_len
) {
    uint32_t sum = 0;
    uint16_t word;

    for (int i = 0; i < 16; i += 2) {
        word = (ip6->src_addr[i] << 8) | ip6->src_addr[i+1];
        sum += word;
    }

    for (int i = 0; i < 16; i += 2) {
        word = (ip6->dst_addr[i] << 8) | ip6->dst_addr[i+1];
        sum += word;
    }

    sum += 0;
    const uint8_t *len_ptr = (const uint8_t*)&udp->len;
    sum += (len_ptr[0] << 8) | len_ptr[1];

    sum += IPPROTO_UDP;

    const uint8_t *udp_hdr = (const uint8_t*)udp;
    for (int i = 0; i < 8; i += 2) {
        word = (udp_hdr[i] << 8) | udp_hdr[i+1];
        sum += word;
    }

    for (size_t i = 0; i < payload_len; i++) {
        if (i % 2 == 0) {
            word = payload[i] << 8;
            if (i+1 < payload_len) word |= payload[i+1];
            sum += word;
        }
    }

    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    uint16_t checksum = ~sum;

    return checksum == 0 ? 0xFFFF : checksum;
}

static void calculate_pdm_metrics(struct pdm_option *pdm,
                                const struct flow_state *flow,
                                const struct timespec *curr_time) {
    pdm->option_type = 0x0F;
    pdm->opt_len = 10;

    uint64_t dtlr_ns = 0;
    uint64_t dtls_ns = 0;
    uint8_t scale_dtlr = 0, scale_dtls = 0;

    pdm->scale_dtlr = scale_dtlr;
    pdm->scale_dtls = scale_dtls;
    pdm->deltatlr = htons((uint16_t)dtlr_ns);
    pdm->deltatls = htons((uint16_t)dtls_ns);

    pdm->psntp = htons(flow->current_psn);
    pdm->psnlr = htons(flow->last_received_psn);
}

int main() {
    static struct flow_state flow = {0};
    if (!flow.initialized) {
        flow.current_psn = 13; // Set to match example's PSN This Packet
        flow.last_received_psn = 0;
        clock_gettime(CLOCK_MONOTONIC, &flow.last_send_time);
        clock_gettime(CLOCK_MONOTONIC, &flow.last_recv_time);
        flow.initialized = 1;
    }

    uint8_t packet[256] = {0};
    struct ipv6_hdr *ip6 = (struct ipv6_hdr *)packet;
    struct dest_opt_hdr *dest_opt = (struct dest_opt_hdr *)(ip6 + 1);
    struct pdm_option *pdm = (struct pdm_option *)dest_opt->options;
    struct udp_hdr *udp = (struct udp_hdr *)(dest_opt + 1);
    uint8_t *dns_payload = (uint8_t *)(udp + 1);

    // IPv6 Header
    ip6->vtf = htonl(0x60000000);
    ip6->next_header = IPPROTO_DSTOPTS;
    ip6->hop_limit = 64;
    inet_pton(AF_INET6, "2409:40e0:1031:2733:2c73:69fe:ae1d:d592", ip6->src_addr);
    inet_pton(AF_INET6, "2406:da1a:8e8:e8cb:97fe:3833:8668:54ad", ip6->dst_addr);

    // Destination Options Header
    dest_opt->next_header = IPPROTO_UDP;
    dest_opt->hdr_ext_len = 1;

    // UDP Header
    udp->src_port = htons(53); // Both ports set to 53
    udp->dst_port = htons(53);
    uint8_t dns_query[] = {
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0c, 't', 'e', 's', 't', 'p', 'r', 'o', 't', 'o', 'c', 'o', 'l',
        0x02, 'i', 'n', 0x00, 0x00, 0x1c, 0x00, 0x01
    };
    memcpy(dns_payload, dns_query, sizeof(dns_query));

    udp->len = htons(sizeof(struct udp_hdr) + sizeof(dns_query));
    size_t total_payload_len = sizeof(struct dest_opt_hdr) + sizeof(struct udp_hdr) + sizeof(dns_query);
    ip6->payload_len = htons(total_payload_len);

    udp->checksum = 0;
    uint16_t calculated_checksum = compute_udp_checksum(ip6, udp, dns_payload, sizeof(dns_query));
    udp->checksum = htons(calculated_checksum);

    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    struct pdm_option pdm_data = {0};
    calculate_pdm_metrics(&pdm_data, &flow, &now);
    memcpy(dest_opt->options, &pdm_data, sizeof(struct pdm_option));
    
    // PadN (0x01 followed by 0x00 for 2 bytes padding)
    dest_opt->options[12] = 0x01; // PadN type
    dest_opt->options[13] = 0x00; // PadN length (0 bytes data)

    flow.last_send_time = now;

    int sock = socket(AF_INET6, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) {
        perror("Failed to create raw socket");
        return EXIT_FAILURE;
    }

    int one = 1;
    if (setsockopt(sock, IPPROTO_IPV6, IPV6_HDRINCL, &one, sizeof(one))) {
        perror("Failed to set IPV6_HDRINCL");
        close(sock);
        return EXIT_FAILURE;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, "wlo1", IFNAMSIZ-1); // Update interface as needed
    if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr)) < 0) {
        perror("Failed to bind to interface");
        close(sock);
        return EXIT_FAILURE;
    }

    struct sockaddr_in6 dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin6_family = AF_INET6;
    memcpy(&dest.sin6_addr, ip6->dst_addr, 16);
    dest.sin6_scope_id = if_nametoindex("wlo1");

    size_t total_len = sizeof(struct ipv6_hdr) + total_payload_len;
    ssize_t sent = sendto(sock, packet, total_len, 0, (struct sockaddr *)&dest, sizeof(dest));
    if (sent < 0) {
        perror("Failed to send packet");
        close(sock);
        return EXIT_FAILURE;
    }

    printf("Sent %zd bytes successfully\n", sent);
    close(sock);

    printf("IPv6 PDM Packet:\n");
    for (size_t i = 0; i < total_len; i++) {
        printf("%02x ", packet[i]);
        if ((i + 1) % 16 == 0) printf("\n");
        else if ((i + 1) % 8 == 0) printf(" ");
    }
    printf("\n");

    return 0;
}