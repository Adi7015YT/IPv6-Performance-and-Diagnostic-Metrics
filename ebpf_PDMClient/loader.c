#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <bpf/bpf.h>

int main() {
    struct bpf_object *obj = NULL;
    int ifindex, err, prog_fd;
    const char *interface = "wlo1"; // Use consistent interface name

    // Get interface index
    ifindex = if_nametoindex(interface);
    if (!ifindex) {
        fprintf(stderr, "Interface not found: %s\n", strerror(errno));
        return 1;
    }

    // Set up TC using tc command directly - more reliable than libbpf TC API
    char cmd[256];
    
    // Clean existing config
    snprintf(cmd, sizeof(cmd), "sudo tc qdisc del dev %s clsact 2>/dev/null", interface);
    system(cmd);
    
    // Create clsact qdisc
    snprintf(cmd, sizeof(cmd), "sudo tc qdisc add dev %s clsact", interface);
    if (system(cmd) != 0) {
        fprintf(stderr, "Failed to create clsact qdisc\n");
        return 1;
    }
    
    // Load BPF object
    obj = bpf_object__open_file("pdm_ebpf.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "BPF open failed: %s\n", strerror(errno));
        return 1;
    }

    // Set correct program type and attach type
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "add_pdm_header");
    if (!prog) {
        fprintf(stderr, "Program not found\n");
        goto cleanup;
    }
    
    // Set program type to BPF_PROG_TYPE_SCHED_CLS
    bpf_program__set_type(prog, BPF_PROG_TYPE_SCHED_CLS);
    
    // Load BPF program
    if ((err = bpf_object__load(obj))) {
        fprintf(stderr, "BPF load failed: %s\n", strerror(-err));
        goto cleanup;
    }

    // Get program fd
    prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0) {
        fprintf(stderr, "Failed to get program FD: %s\n", strerror(-prog_fd));
        goto cleanup;
    }

    // Attach using tc command - more reliable than libbpf TC API
    snprintf(cmd, sizeof(cmd), 
             "sudo tc filter add dev %s egress bpf direct-action obj pdm_ebpf.o sec classifier", 
             interface);
    
    if (system(cmd) != 0) {
        fprintf(stderr, "Failed to attach BPF program\n");
        goto cleanup;
    }

    printf("Success! Program attached to %s. Press Enter to detach...\n", interface);
    getchar();

cleanup:
    // Clean up using tc command
    snprintf(cmd, sizeof(cmd), "sudo tc filter del dev %s egress", interface);
    system(cmd);
    
    bpf_object__close(obj);
    return 0;
}