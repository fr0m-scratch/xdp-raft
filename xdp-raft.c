#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <net/if.h>
#include <linux/if_link.h>
#include "xdp-raft.skel.h"  // Include the generated skeleton header

static struct xdp_raft_bpf *skel = NULL;

void cleanup_function(void) {
    if (skel) {
        xdp_raft_bpf__destroy(skel);
        printf("Cleaned up and destroyed XDP program skeleton.\n");
    }
}

static int load_xdp_program(const char *iface) {
    int ifindex;
    int err;

    skel = xdp_raft_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return -1;
    }

    ifindex = if_nametoindex(iface);
    if (ifindex == 0) {
        fprintf(stderr, "Error finding interface: %s\n", iface);
        return -1;
    }

    err = xdp_raft_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach XDP program: %d\n", err);
        return -1;
    }

    printf("Successfully attached XDP program to interface: %s\n", iface);

    
    atexit(cleanup_function);

    return 0;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <interface>\n", argv[0]);
        return 1;
    }

    const char *iface = argv[1];

    if (load_xdp_program(iface) < 0) {
        fprintf(stderr, "Failed to load and attach XDP program\n");
        return 1;
    }

    printf("XDP program loaded and attached. Press Ctrl+C to exit.\n");

    
    while (1) {
        sleep(1);
    }

    return 0;
}
