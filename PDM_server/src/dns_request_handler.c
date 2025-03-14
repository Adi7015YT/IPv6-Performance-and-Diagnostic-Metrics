#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>

#define DNS_PORT 53

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
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} dns_requests SEC(".maps");

SEC("tc/ingress")
int dns_request_handler(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    // Parse Ethernet header
    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return TC_ACT_OK;
    if (eth->h_proto != bpf_htons(ETH_P_IPV6))
        return TC_ACT_OK;

    // Parse IPv6 header
    struct ipv6hdr *ip6h = (void *)(eth + 1);
    if ((void *)(ip6h + 1) > data_end)
        return TC_ACT_OK;
    if (ip6h->nexthdr != IPPROTO_UDP)
        return TC_ACT_OK;

    // Parse UDP header
    struct udphdr *udph = (void *)(ip6h + 1);
    if ((void *)(udph + 1) > data_end)
        return TC_ACT_OK;
    if (udph->dest != bpf_htons(DNS_PORT))
        return TC_ACT_OK;

    // Extract flow key
    struct flow_key key = {
        .saddr = ip6h->saddr,
        .daddr = ip6h->daddr,
        .sport = udph->source,
        .dport = udph->dest,
        .protocol = IPPROTO_UDP
    };

    // Update map with current timestamp
    __u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&dns_requests, &key, &ts, BPF_ANY);
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";