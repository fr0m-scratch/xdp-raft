#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

static __inline __u16 bpf_htons(__u16 x) {
    return __builtin_bswap16(x);
}

static __inline __u16 bpf_ntohs(__u16 x) {
    return __builtin_bswap16(x);
}
struct raft_params {
    __u32 term;
    __u32 leader;
    __u32 prev_log_index;
    __u32 prev_log_term;
    __u32 commit_index;
    __u32 opNum;
};

struct raft_params* parse(void *data, void *data_end) {
    struct ethhdr *eth = data;
    struct iphdr *ip = (void *)(eth + 1);
    struct tcphdr *tcp = (void *)(ip + 1);
    void *payload = (void *)(tcp + 1);

    if ((void *)(payload + sizeof(struct raft_params)) > data_end)
        return NULL;

    return (struct raft_params *)payload;
}

static __inline int serialize_heartbeat_response(void *data, void *data_end, struct raft_params *params) {
    struct ethhdr *eth = data;
    struct iphdr *ip = (void *)(eth + 1);
    struct tcphdr *tcp = (void *)(ip + 1);
    void *payload = (void *)(tcp + 1);

    if ((void *)(payload + sizeof(struct raft_params)) > data_end)
        return XDP_DROP;

    __builtin_memcpy(payload, params, sizeof(struct raft_params));
    return XDP_TX;
}

static __inline void print_tcp_packet(void *data, void *data_end) {
    struct ethhdr *eth = data;
    struct iphdr *ip = (void *)(eth + 1);
    struct tcphdr *tcp = (void *)(ip + 1);

    if ((void *)(tcp + 1) > data_end)
        return;

    bpf_printk("TCP packet: src_ip=%u.%u.%u.%u src_port=%u dst_ip=%u.%u.%u.%u dst_port=%u\n",
        ip->saddr & 0xFF, (ip->saddr >> 8) & 0xFF, (ip->saddr >> 16) & 0xFF, (ip->saddr >> 24) & 0xFF,
        bpf_ntohs(tcp->source),
        ip->daddr & 0xFF, (ip->daddr >> 8) & 0xFF, (ip->daddr >> 16) & 0xFF, (ip->daddr >> 24) & 0xFF,
        bpf_ntohs(tcp->dest));
}

SEC("xdp")
int xdp_heartbeat_dispatcher(struct xdp_md *ctx) {
    bpf_printk("xdp_raft_monitor\n");
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = (void *)(eth + 1);
        if ((void *)(ip + 1) > data_end)
            return XDP_PASS;

        if (ip->protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = (void *)(ip + 1);
            if ((void *)(tcp + 1) > data_end)
                return XDP_PASS;
            
            print_tcp_packet(data, data_end);

            if (tcp->dest == bpf_htons(9181) ||
                tcp->dest == bpf_htons(9182) ||
                tcp->dest == bpf_htons(9183)) {
                struct raft_params* params = parse(data, data_end);
                if (!params)
                    return XDP_PASS;

                switch (params->opNum) {
                    case 11: // zookeeper opNum for heartbeat
                        return serialize_heartbeat_response(data, data_end, params);
                    default:
                        bpf_printk("Unknown Raft operation: %u\n", params->opNum);
                }
            }
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";