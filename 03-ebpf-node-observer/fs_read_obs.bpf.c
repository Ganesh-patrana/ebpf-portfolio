#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

// BPF Hash Map: Maps Process Name (Key) -> VFS Read Count (Value)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, char[16]);
    __type(value, u64);
} vfs_read_counts SEC(".maps");

// Kprobe: Triggers dynamically whenever the kernel executes vfs_read()
SEC("kprobe/vfs_read")
int trace_vfs_read(struct pt_regs *ctx) {
    // 1. Get process name
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));

    // 2. Look up the current read count for this process
    u64 *count = bpf_map_lookup_elem(&vfs_read_counts, &comm);
    
    if (count) {
        // 3. Atomically increment if exists
        __sync_fetch_and_add(count, 1);
    } else {
        // 4. Initialize to 1 if new
        u64 init_val = 1;
        bpf_map_update_elem(&vfs_read_counts, &comm, &init_val, BPF_ANY);
    }
    
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
