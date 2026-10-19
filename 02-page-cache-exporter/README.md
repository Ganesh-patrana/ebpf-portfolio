# Phase 2: Page Cache Exporter (eBPF + Go)
This project uses the Cilium eBPF library to load a custom C-based kprobe into the Linux kernel. It hooks into `mark_page_accessed` to track in-memory page cache hits per process, exporting the data to user-space via an eBPF Hash Map.
