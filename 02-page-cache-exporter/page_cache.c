//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, __u64);
} cache_hits SEC(".maps");

SEC("kprobe/mark_page_accessed")
int count_cache_hits(void *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u64 *count, init_val = 1;

    count = bpf_map_lookup_elem(&cache_hits, &pid);
    if (count) {
        __sync_fetch_and_add(count, 1);
    } else {
        bpf_map_update_elem(&cache_hits, &pid, &init_val, BPF_ANY);
    }
    return 0;
}

char __license[] SEC("license") = "Dual MIT/GPL";
