#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_packet_counter(struct xdp_md *ctx)
{
    bpf_printk("Packet received!");
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";