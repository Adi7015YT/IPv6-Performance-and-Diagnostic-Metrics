#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/pkt_cls.h>
#include <linux/in.h>
#include "../include/pdm_common.h"

struct flow_key {
    struct in6_addr saddr;
    struct in6_addr daddr;
    __be16 sport;
    __be16 dport;
    __u8 protocol;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, struct flow_key);
    __type(value, __u64);
} dns_requests SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} psn_counter SEC(".maps");

// Add new map for tracking last received PSN
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, struct flow_key);
    __type(value, __u32);
} last_psn SEC(".maps");

static __always_inline __u32 get_next_psn() {
    __u32 key = 0, *val;
    val = bpf_map_lookup_elem(&psn_counter, &key);
    if (!val) return 1;
    
    __sync_fetch_and_add(val, 1);
    return *val;
}

SEC("tc/egress")
int handle_egress(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    
    // Check if we have a complete Ethernet + IPv6 + UDP header
    if (data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + sizeof(struct udphdr) > data_end)
        return TC_ACT_OK;
    
    struct ethhdr *eth = data;
    struct ipv6hdr *ip6 = (void *)(eth + 1);
    struct udphdr *udp = (void *)(ip6 + 1);

    struct flow_key req_key = {
        .saddr = ip6->daddr,
        .daddr = ip6->saddr,
        .sport = udp->dest,
        .dport = udp->source,
        .protocol = IPPROTO_UDP
    };

    // Look for PDM in incoming packet
    struct ipv6_opt_hdr *in_dopt = (void *)(ip6 + 1);
    if (ip6->nexthdr == IPPROTO_DSTOPTS && 
        (void *)(in_dopt + 1) + sizeof(struct pdm_metrics) <= data_end) {
        struct pdm_metrics *in_pdm = (void *)(in_dopt + 1);
        if (in_pdm->type == PDM_OPT_TYPE) {
            __u32 received_psn = bpf_ntohs(in_pdm->psntp);
            bpf_map_update_elem(&last_psn, &req_key, &received_psn, BPF_ANY);
        }
    }

    __u64 *req_ts = bpf_map_lookup_elem(&dns_requests, &req_key);
    if (!req_ts) return TC_ACT_OK;

    __u64 res_ts = bpf_ktime_get_ns();
    __u16 scaled_delta = (res_ts - *req_ts) >> SCALE_FACTOR;
    __u32 psn = get_next_psn();

    // Make room for Destination Options header
    if (bpf_skb_adjust_room(skb, sizeof(struct ipv6_opt_hdr) + 
                                 sizeof(struct pdm_metrics) + 4, 
                                 BPF_ADJ_ROOM_MAC, 0))
        return TC_ACT_OK;

    // After adjusting room, we need to re-acquire pointers and check bounds
    data = (void *)(long)skb->data;
    data_end = (void *)(long)skb->data_end;
    
    // Re-verify packet boundaries after adjustment
    if (data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + 
        sizeof(struct ipv6_opt_hdr) + sizeof(struct pdm_metrics) + 4 > data_end)
        return TC_ACT_OK;
        
    eth = data;
    ip6 = (void *)(eth + 1);
    
    struct ipv6_opt_hdr *dopt = (void *)(ip6 + 1);
    dopt->nexthdr = IPPROTO_UDP;
    dopt->hdrlen = (sizeof(struct pdm_metrics) + 4) / 8 - 1;

    struct pdm_metrics *pdm = (void *)(dopt + 1);
    pdm->type = PDM_OPT_TYPE;
    pdm->len = PDM_OPT_LEN;
    pdm->scale_dtlr = SCALE_FACTOR;
    pdm->scale_dtls = 0;  // Initialize to 0
    pdm->psntp = bpf_htons(psn);
    
    // Set PSNLR from tracked value
    __u32 *last_received_psn = bpf_map_lookup_elem(&last_psn, &req_key);
    pdm->psnlr = last_received_psn ? bpf_htons(*last_received_psn) : 0;
    
    pdm->deltatlr = bpf_htons(scaled_delta);
    pdm->deltatls = 0;  // Initialize to 0

    // Updated padding implementation
    __u8 *pad = (void *)(pdm + 1);
    if ((void *)(pad + 2) > data_end)
        return TC_ACT_OK;
    
    pad[0] = 0x00;  // Pad1
    pad[1] = 0x00;  // Pad1
    
    ip6->nexthdr = IPPROTO_DSTOPTS;
    __u16 payload_len = bpf_ntohs(ip6->payload_len) + 
                        sizeof(struct ipv6_opt_hdr) + 
                        sizeof(struct pdm_metrics) + 4;
    ip6->payload_len = bpf_htons(payload_len);

    bpf_map_delete_elem(&dns_requests, &req_key);
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";