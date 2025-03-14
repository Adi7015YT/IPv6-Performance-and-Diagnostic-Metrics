#ifndef PDM_COMMON_H
#define PDM_COMMON_H

#define PDM_OPT_TYPE 0x0F
#define PDM_OPT_LEN 10
#define SCALE_FACTOR 20

struct pdm_metrics {
    __u8 type;
    __u8 len;
    __u8 scale_dtlr;
    __u8 scale_dtls;
    __be16 psntp;
    __be16 psnlr;
    __be16 deltatlr;
    __be16 deltatls;
} __attribute__((packed));

#endif
