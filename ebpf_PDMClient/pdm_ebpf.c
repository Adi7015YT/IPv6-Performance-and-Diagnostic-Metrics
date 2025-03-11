#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/pkt_cls.h>
#include <linux/in.h>

#define IPPROTO_DSTOPTS 60

struct pdm_opt {
    __u8 type;
    __u8 len;
    __u8 scale_dtlr;
    __u8 scale_dtls;
    __be16 psntp;
    __be16 psnlr;
    __be16 deltatlr;
    __be16 deltatls;
};

struct dest_opt_hdr {
    __u8 next_header;
    __u8 hdr_ext_len;
    // Options data follows
};

SEC("classifier")
int add_pdm_header(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    // Parse Ethernet header
    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return TC_ACT_OK;
    
    if (eth->h_proto != bpf_htons(ETH_P_IPV6))
        return TC_ACT_OK;

    // Parse IPv6 header
    struct ipv6hdr *ip6 = data + sizeof(*eth);
    if ((void *)(ip6 + 1) > data_end)
        return TC_ACT_OK;

    // Only process UDP packets
    if (ip6->nexthdr != IPPROTO_UDP)
        return TC_ACT_OK;

    // Parse UDP header
    struct udphdr *udp = (void *)(ip6 + 1);
    if ((void *)(udp + 1) > data_end)
        return TC_ACT_OK;

    // Only modify DNS queries (destination port 53)
    if (udp->dest != bpf_htons(53))
        return TC_ACT_OK;

    // Store original values
    __u8 orig_nexthdr = ip6->nexthdr;
    __be16 orig_payload = ip6->payload_len;

    // Calculate size of Destination Options header (header + options)
    // PDM option (12 bytes) + PadN (2 bytes) + basic header (2 bytes)
    int dest_opt_size = sizeof(struct dest_opt_hdr) + 14; // 16 bytes total

    // Make room for Destination Options header
    if (bpf_skb_adjust_room(skb, dest_opt_size, BPF_ADJ_ROOM_NET, 0))
        return TC_ACT_OK;

    // Re-validate pointers after adjustment
    data = (void *)(long)skb->data;
    data_end = (void *)(long)skb->data_end;
    
    eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;
    
    ip6 = (void *)(eth + 1);
    if ((void *)(ip6 + 1) > data_end)
        return TC_ACT_OK;

    // Update IPv6 header
    ip6->nexthdr = IPPROTO_DSTOPTS;
    ip6->payload_len = bpf_htons(bpf_ntohs(orig_payload) + dest_opt_size);

    // Add Destination Options header
    struct dest_opt_hdr *dopt = (void *)(ip6 + 1);
    if ((void *)(dopt + 1) > data_end)
        return TC_ACT_OK;

    dopt->next_header = orig_nexthdr;
    // hdr_ext_len is in 8-byte units, minus the first 8 bytes
    // 16 bytes total - 8 = 8, so length field = 1
    dopt->hdr_ext_len = 1; 

    // Validate we have enough space for options
    unsigned char *opt_ptr = (unsigned char *)(dopt + 1);
    if (opt_ptr + 14 > (unsigned char *)data_end)
        return TC_ACT_OK;

    // Set PDM option
    opt_ptr[0] = 0x0F;    // Option type (PDM)
    opt_ptr[1] = 0x0A;    // Option length (10 bytes of data)
    opt_ptr[2] = 0x00;    // scale_dtlr
    opt_ptr[3] = 0x00;    // scale_dtls
    
    // Set packet sequence numbers and deltas
    // psntp - Packet Sequence Number This Packet
    *(__be16 *)(opt_ptr + 4) = bpf_htons(13);
    // psnlr - Packet Sequence Number Last Received
    *(__be16 *)(opt_ptr + 6) = bpf_htons(0);
    // deltatlr - Delta Time Last Received
    *(__be16 *)(opt_ptr + 8) = bpf_htons(0);
    // deltatls - Delta Time Last Sent
    *(__be16 *)(opt_ptr + 10) = bpf_htons(0);

    // Add PadN option (for 8-byte alignment)
    opt_ptr[12] = 0x01;   // PadN option type
    opt_ptr[13] = 0x00;   // PadN length (0 bytes of padding)

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";