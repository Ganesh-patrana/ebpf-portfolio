#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

// 1. Define a BPF Hash Map
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, char[16]); // Key: Process name (16 chars max)
    __type(value, u64);    // Value: Execution count
} exec_counts SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_exec(void *ctx) {
    // 2. Get the process name
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));

    // 3. Look up the current count for this process name in the map
    u64 *count = bpf_map_lookup_elem(&exec_counts, &comm);
    
    if (count) {
        // 4. If it exists, atomically increment the value
        __sync_fetch_and_add(count, 1);
    } else {
        // 5. If it does not exist, initialize it to 1
        u64 init_val = 1;
        bpf_map_update_elem(&exec_counts, &comm, &init_val, BPF_ANY);
    }
    
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
