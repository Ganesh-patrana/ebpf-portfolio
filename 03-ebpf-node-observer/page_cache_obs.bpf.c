#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

// 1. Define the telemetry structure that will be the "Value" in our map
struct cache_stat {
    u64 accesses; // Hits + Misses
    u64 misses;   // Just Misses
};

// 2. Define the BPF Hash Map: Process Name (Key) -> cache_stat (Value)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, char[16]);
    __type(value, struct cache_stat);
} cache_stats SEC(".maps");

// 3. Probe 1: Total Cache Accesses
SEC("kprobe/folio_mark_accessed")
int trace_folio_access(struct pt_regs *ctx) {
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));

    struct cache_stat *stat = bpf_map_lookup_elem(&cache_stats, &comm);
    if (stat) {
        // Atomically increment just the 'accesses' field
        __sync_fetch_and_add(&stat->accesses, 1);
    } else {
        struct cache_stat init_val = {};
        init_val.accesses = 1;
        init_val.misses = 0;
        bpf_map_update_elem(&cache_stats, &comm, &init_val, BPF_ANY);
    }
    return 0;
}

// 4. Probe 2: Cache Misses (Disk I/O)
SEC("kprobe/filemap_add_folio")
int trace_folio_miss(struct pt_regs *ctx) {
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));

    struct cache_stat *stat = bpf_map_lookup_elem(&cache_stats, &comm);
    if (stat) {
        // Atomically increment just the 'misses' field
        __sync_fetch_and_add(&stat->misses, 1);
    } else {
        struct cache_stat init_val = {};
        init_val.accesses = 0;
        init_val.misses = 1;
        bpf_map_update_elem(&cache_stats, &comm, &init_val, BPF_ANY);
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
