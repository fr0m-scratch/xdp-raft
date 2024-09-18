#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>

SEC("tracepoint/net/netif_receive_skb")
int tracepoint__net__netif_receive_skb(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct iphdr *iph = data + skb->network_header;
    
    if ((void *)iph + sizeof(*iph) > data_end)
        return 0;

    if (iph->protocol == IPPROTO_TCP || iph->protocol == IPPROTO_UDP) {
        struct tcphdr *th = data + skb->transport_header;

        if ((void *)th + sizeof(*th) > data_end)
            return 0;

        __be16 dst_port = th->dest;

        dst_port = __builtin_bswap16(dst_port);

        if (dst_port == 9000 || dst_port == 9001) {
            bpf_printk("Received packet: SRC=%pI4 DST=%pI4 DST_PORT=%d\n", 
                       &iph->saddr, &iph->daddr, dst_port);
        }
    }

    return 0;
}

char _license[] SEC("license") = "GPL";
