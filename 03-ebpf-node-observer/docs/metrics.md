# Prometheus Metrics Design

## Metrics Exposed

### 1. `ebpf_page_cache_accesses_total`
* **Type:** Counter
* **Labels:** `process_name`
* **Meaning:** The total number of times a process successfully accessed a memory folio in the Linux page cache (via `folio_mark_accessed`).
* **Limitations:** Includes both hits and misses. High-frequency accesses might be undercounted during extreme CPU starvation due to eBPF map update collisions, though atomic operations mitigate this heavily.

### 2. `ebpf_page_cache_misses_total`
* **Type:** Counter
* **Labels:** `process_name`
* **Meaning:** The total number of times the kernel had to fetch file data from the block layer (disk) and allocate a new page cache folio (via `filemap_add_folio`).
* **Limitations:** Does not account for `O_DIRECT` reads.

## Cardinality Safety
We intentionally drop the Process ID (PID) at the userspace boundary. eBPF can track PIDs internally if needed for advanced debugging, but we aggregate by `process_name` before exporting to Prometheus to prevent time-series cardinality explosions.
