#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv6.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <net/ipv6.h>
#include <linux/hashtable.h>
#include <linux/jhash.h>

#define LOG_FILE "/var/log/pdm_packets.log"
#define PDM_OPT_TYPE 0x0F
#define MINIMUM_PDM_HEADER_SIZE 8
#define BYTES_PER_LINE 16
#define DNS_PORT 53
#define HT_SIZE_BITS 10

static struct nf_hook_ops nfho_ingress, nfho_egress;
static struct file *log_file;
static DEFINE_MUTEX(log_mutex);
static DEFINE_HASHTABLE(dns_requests, HT_SIZE_BITS);
static DEFINE_SPINLOCK(req_lock);
static atomic_t psn_counter = ATOMIC_INIT(1);

struct pdm_option {
    u8 option_type;
    u8 opt_len;
    u8 scale_dtlr;
    u8 scale_dtls;
    __be16 psntp;
    __be16 psnlr;
    __be16 deltatlr;
    __be16 deltatls;
};

struct flow_key {
    struct in6_addr saddr;
    struct in6_addr daddr;
    __be16 sport;
    __be16 dport;
};

struct dns_request {
    struct hlist_node node;
    struct flow_key key;
    ktime_t timestamp;
};

static u32 flow_hash(const struct flow_key *key)
{
    return jhash2((u32 *)key, sizeof(*key)/sizeof(u32), 0);
}

static struct dns_request *find_request(const struct flow_key *key)
{
    struct dns_request *req;
    u32 hash = flow_hash(key);

    hash_for_each_possible(dns_requests, req, node, hash) {
        if (ipv6_addr_equal(&req->key.saddr, &key->saddr) &&
            ipv6_addr_equal(&req->key.daddr, &key->daddr) &&
            req->key.sport == key->sport &&
            req->key.dport == key->dport) {
            return req;
        }
    }
    return NULL;
}

static void write_hexdump(struct file *file, void *data, size_t len, loff_t *pos)
{
    unsigned char *buf = (unsigned char *)data;
    char line[256];
    int line_len, i, j;
    char hex[50], ascii[20];
    
    kernel_write(file, "\n==== PACKET HEXDUMP ====\n", 26, pos);
    
    for (i = 0; i < len; i += BYTES_PER_LINE) {
        memset(hex, 0, sizeof(hex));
        memset(ascii, 0, sizeof(ascii));
        
        for (j = 0; j < BYTES_PER_LINE && i + j < len; j++) {
            char tmp[4];
            snprintf(tmp, sizeof(tmp), "%02x ", buf[i + j]);
            strcat(hex, tmp);
            ascii[j] = (buf[i + j] >= 32 && buf[i + j] <= 126) ? 
                      buf[i + j] : '.';
        }
        
        for (; j < BYTES_PER_LINE; j++) {
            strcat(hex, "   ");
            ascii[j] = ' ';
        }
        
        line_len = snprintf(line, sizeof(line), 
                          "%04x: %s| %s\n", i, hex, ascii);
        kernel_write(file, line, line_len, pos);
    }
    
    kernel_write(file, "==== END HEXDUMP ====\n\n", 23, pos);
}

static void log_pdm_details(struct file *file, struct pdm_option *pdm, loff_t *pos)
{
    char buf[256];
    int len = snprintf(buf, sizeof(buf),
        "PDM Details:\n"
        "  Type: 0x%02x\n  Length: %u\n  Scale DTLR: 0x%02x\n"
        "  Scale DTLS: 0x%02x\n  PSNTP: 0x%04x\n  PSNLR: 0x%04x\n"
        "  DeltaTLR: 0x%04x\n  DeltaTLS: 0x%04x\n",
        pdm->option_type, pdm->opt_len, pdm->scale_dtlr,
        pdm->scale_dtls, ntohs(pdm->psntp), ntohs(pdm->psnlr),
        ntohs(pdm->deltatlr), ntohs(pdm->deltatls));
        
    kernel_write(file, buf, len, pos);
}

static unsigned int ingress_handler(void *priv, struct sk_buff *skb,
                   const struct nf_hook_state *state)
{
    struct ipv6hdr *ip6h;
    struct udphdr *udph;
    struct ipv6_opt_hdr *dsthdr;
    unsigned char *opt_ptr;
    u8 nexthdr;
    int offset = 0, hdrlen = 0;
    bool pdm_found = false;
    struct pdm_option *pdm = NULL;
    loff_t pos = 0;
    char log_buf[512];
    char src_addr[50], dst_addr[50];

    if (!skb || !pskb_may_pull(skb, sizeof(struct ipv6hdr)))
        return NF_ACCEPT;

    ip6h = ipv6_hdr(skb);
    if (ip6h->version != 6)
        return NF_ACCEPT;

    nexthdr = ip6h->nexthdr;
    offset = sizeof(struct ipv6hdr);
    
    while (ipv6_ext_hdr(nexthdr)) {
        if (!pskb_may_pull(skb, offset + sizeof(struct ipv6_opt_hdr)))
            break;
            
        dsthdr = (struct ipv6_opt_hdr *)(skb->data + offset);
        
        if (nexthdr == IPPROTO_DSTOPTS) {
            hdrlen = (dsthdr->hdrlen + 1) << 3;
            
            if (!pskb_may_pull(skb, offset + hdrlen))
                break;
                
            opt_ptr = (unsigned char *)dsthdr + 2;
            int opt_remaining = hdrlen - 2;
            
            while (opt_remaining > 0) {
                u8 opt_type = *opt_ptr;
                if (opt_type == IPV6_TLV_PAD1) {
                    opt_ptr++;
                    opt_remaining--;
                    continue;
                }
                
                if (opt_remaining < 2) break;
                u8 opt_len = *(opt_ptr + 1);
                
                if (opt_type == PDM_OPT_TYPE && 
                    opt_len + 2 <= opt_remaining &&
                    opt_len >= MINIMUM_PDM_HEADER_SIZE) {
                    pdm = (struct pdm_option *)opt_ptr;
                    pdm_found = true;
                    break;
                }
                
                opt_ptr += opt_len + 2;
                opt_remaining -= opt_len + 2;
            }
        }
        
        if (ipv6_ext_hdr(nexthdr)) {
            nexthdr = dsthdr->nexthdr;
            offset += hdrlen;
        } else {
            break;
        }
    }
    
    if (!pdm_found || nexthdr != IPPROTO_UDP)
        return NF_ACCEPT;
        
    if (!pskb_may_pull(skb, offset + sizeof(struct udphdr)))
        return NF_ACCEPT;
        
    udph = (struct udphdr *)(skb->data + offset);
    
    snprintf(src_addr, sizeof(src_addr), "%pI6c", &ip6h->saddr);
    snprintf(dst_addr, sizeof(dst_addr), "%pI6c", &ip6h->daddr);
    
    mutex_lock(&log_mutex);
    
    int log_len = snprintf(log_buf, sizeof(log_buf), 
        "\n--- INGRESS PDM PACKET [%llu] ---\n"
        "SRC: %s:%u\nDST: %s:%u\n",
        ktime_get_real_seconds(),
        src_addr, ntohs(udph->source),
        dst_addr, ntohs(udph->dest));
        
    kernel_write(log_file, log_buf, log_len, &pos);
    
    if (pdm)
        log_pdm_details(log_file, pdm, &pos);
    
    void *file_data = kmalloc(skb->len, GFP_KERNEL);
    if (file_data) {
        if (skb_copy_bits(skb, 0, file_data, skb->len) == 0) {
            write_hexdump(log_file, file_data, skb->len, &pos);
            kernel_write(log_file, "--- RAW DATA ---\n", 17, &pos);
            kernel_write(log_file, file_data, skb->len, &pos);
            kernel_write(log_file, "\n--- END ---\n\n", 14, &pos);
        }
        kfree(file_data);
    }
    
    mutex_unlock(&log_mutex);
    return NF_ACCEPT;
}

static unsigned int egress_handler(void *priv, struct sk_buff *skb,
                   const struct nf_hook_state *state)
{
    struct ipv6hdr *ip6h;
    struct udphdr *udph;
    struct flow_key key;
    loff_t pos = 0;
    char log_buf[512];
    char src_addr[50], dst_addr[50];

    if (!skb || !pskb_may_pull(skb, sizeof(struct ipv6hdr) + sizeof(struct udphdr)))
        return NF_ACCEPT;

    ip6h = ipv6_hdr(skb);
    if (ip6h->version != 6 || ip6h->nexthdr != IPPROTO_UDP)
        return NF_ACCEPT;

    udph = udp_hdr(skb);
    if (udph->dest != htons(DNS_PORT))
        return NF_ACCEPT;

    memcpy(&key.saddr, &ip6h->saddr, sizeof(key.saddr));
    memcpy(&key.daddr, &ip6h->daddr, sizeof(key.daddr));
    key.sport = udph->source;
    key.dport = udph->dest;

    struct dns_request *req = kzalloc(sizeof(*req), GFP_ATOMIC);
    if (!req)
        return NF_ACCEPT;

    memcpy(&req->key, &key, sizeof(key));
    req->timestamp = ktime_get_real_ns();

    spin_lock_bh(&req_lock);
    hash_add(dns_requests, &req->node, flow_hash(&key));
    spin_unlock_bh(&req_lock);

    snprintf(src_addr, sizeof(src_addr), "%pI6c", &ip6h->saddr);
    snprintf(dst_addr, sizeof(dst_addr), "%pI6c", &ip6h->daddr);

    mutex_lock(&log_mutex);
    
    int log_len = snprintf(log_buf, sizeof(log_buf), 
        "\n--- EGRESS DNS REQUEST [%llu] ---\n"
        "SRC: %s:%u\nDST: %s:%u\n",
        ktime_get_real_seconds(),
        src_addr, ntohs(udph->source),
        dst_addr, ntohs(udph->dest));
        
    kernel_write(log_file, log_buf, log_len, &pos);
    
    mutex_unlock(&log_mutex);
    return NF_ACCEPT;
}

static int __init pdm_init(void)
{
    log_file = filp_open(LOG_FILE, O_CREAT|O_WRONLY|O_APPEND, 0644);
    if (IS_ERR(log_file)) {
        printk(KERN_ERR "PDM logger: Failed to open log file (%ld)\n", PTR_ERR(log_file));
        return PTR_ERR(log_file);
    }

    char header[128];
    loff_t pos = 0;
    int len = snprintf(header, sizeof(header),
              "\n=== PDM CAPTURE STARTED [%llu] ===\n\n",
              ktime_get_real_seconds());
    kernel_write(log_file, header, len, &pos);

    nfho_ingress.hook = ingress_handler;
    nfho_ingress.hooknum = NF_INET_PRE_ROUTING;
    nfho_ingress.pf = NFPROTO_IPV6;
    nfho_ingress.priority = NF_IP6_PRI_FIRST;
    
    nfho_egress.hook = egress_handler;
    nfho_egress.hooknum = NF_INET_POST_ROUTING;
    nfho_egress.pf = NFPROTO_IPV6;
    nfho_egress.priority = NF_IP6_PRI_FIRST;
    
    if (nf_register_net_hook(&init_net, &nfho_ingress) ||
        nf_register_net_hook(&init_net, &nfho_egress)) {
        filp_close(log_file, NULL);
        printk(KERN_ERR "PDM logger: Hook registration failed\n");
        return -EFAULT;
    }

    printk(KERN_INFO "PDM logger: Module loaded, logging to %s\n", LOG_FILE);
    return 0;
}

static void __exit pdm_exit(void)
{
    nf_unregister_net_hook(&init_net, &nfho_ingress);
    nf_unregister_net_hook(&init_net, &nfho_egress);

    struct dns_request *req;
    struct hlist_node *tmp;
    int bkt;

    hash_for_each_safe(dns_requests, bkt, tmp, req, node) {
        hash_del(&req->node);
        kfree(req);
    }

    char footer[128];
    loff_t pos = 0;
    int len = snprintf(footer, sizeof(footer),
                     "\n=== PDM CAPTURE ENDED [%llu] ===\n",
                     ktime_get_real_seconds());
    kernel_write(log_file, footer, len, &pos);
    
    filp_close(log_file, NULL);
    printk(KERN_INFO "PDM logger: Module unloaded\n");
}

module_init(pdm_init);
module_exit(pdm_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Debarghya");
MODULE_DESCRIPTION("IPv6 PDM Packet Logger with Ingress/Egress Support");