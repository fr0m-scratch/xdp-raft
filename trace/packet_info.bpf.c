#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>

#define PORT_9234 9234
#define PORT_9235 9235
#define PORT_9236 9236

static __inline __u16 bpf_htons(__u16 x) {
    return __builtin_bswap16(x);
}

static __inline __u16 bpf_ntohs(__u16 x) {
    return __builtin_bswap16(x);
}

SEC("xdp")
int packet_filter(struct xdp_md *ctx) {
    void *data_end = (void *)(unsigned long)ctx->data_end;
    void *data = (void *)(unsigned long)ctx->data;
    struct ethhdr *eth = data;
    
    // eth
    if (eth + 1 > data_end) return XDP_PASS;

    // IP
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *iph = data + sizeof(struct ethhdr);
    if ((void *)iph + sizeof(*iph) > data_end) return XDP_PASS;

    // UDP/TCP
    if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udph = (void *)iph + sizeof(struct iphdr);
        if ((void *)udph + sizeof(*udph) > data_end) return XDP_PASS;

        if (bpf_ntohs(udph->source) == PORT_9234 || bpf_ntohs(udph->source) == PORT_9235 || bpf_ntohs(udph->source) == PORT_9236 ||
            bpf_ntohs(udph->dest) == PORT_9234 || bpf_ntohs(udph->dest) == PORT_9235 || bpf_ntohs(udph->dest) == PORT_9236) {
            
            bpf_printk("UDP packet from port %d to port %d\n", bpf_ntohs(udph->source), bpf_ntohs(udph->dest));
        }
    } else if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = (void *)iph + sizeof(struct iphdr);
        if ((void *)tcph + sizeof(*tcph) > data_end) return XDP_PASS;

        if (bpf_ntohs(tcph->source) == PORT_9234 || bpf_ntohs(tcph->source) == PORT_9235 || bpf_ntohs(tcph->source) == PORT_9236 ||
            bpf_ntohs(tcph->dest) == PORT_9234 || bpf_ntohs(tcph->dest) == PORT_9235 || bpf_ntohs(tcph->dest) == PORT_9236) {
            
            bpf_printk("TCP packet from port %d to port %d\n", bpf_ntohs(tcph->source), bpf_ntohs(tcph->dest));
        }
    }

    // Allow the packet to pass without modification
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
