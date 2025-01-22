// xdp_program.c (BPF part)
#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

BPF_TABLE("hash", __be32, u32, blocked_ips, 1024);
BPF_PERF_OUTPUT(events);

struct data_t {
    __be32 source_ip;
    __be32 dest_ip;
};

int xdp_drop(struct {ctxtype} *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void*)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = (void*)(eth + 1);
        if ((void*)(ip + 1) > data_end)
            return XDP_PASS;

        __be32 source_ip = ip->daddr;
        __be32 dest_ip = ip->saddr;

        u32 *blocked = blocked_ips.lookup(&dest_ip);
        if (blocked) {
            return XDP_DROP;
        } else {
            struct data_t data = {};
            data.source_ip = source_ip;
            data.dest_ip = dest_ip;
            events.perf_submit(ctx, &data, sizeof(data));
            return XDP_PASS;
        }
    }

    return XDP_PASS;
}
