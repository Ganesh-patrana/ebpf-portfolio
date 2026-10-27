# eBPF Node Observer

A production-grade eBPF agent designed to track Linux page-cache efficiency and filesystem block I/O at the kernel level. Built with C, Go, and deployed as a Kubernetes DaemonSet, this observer exposes low-level memory management telemetry to Prometheus without high-cardinality bottlenecks.

## Architecture

This project spans the kernel-userspace boundary using the modern `cilium/ebpf` framework:

1.  **Kernel Space (C & Clang):** 
    *   Uses dynamic `kprobes` attached to modern Linux 6.x folio subsystems (`folio_mark_accessed` and `filemap_add_folio`).
    *   Aggregates hits and disk-read misses in a highly efficient BPF Hash Map using atomic hardware instructions (`__sync_fetch_and_add`) to prevent race conditions during heavy I/O.
2.  **User Space (Go):** 
    *   Statically compiled Go daemon that loads the eBPF bytecode via `bpf2go`.
    *   Polls the BPF Hash Map asynchronously and calculates metric deltas.
3.  **Observability (Prometheus):** 
    *   Translates absolute kernel counters into Prometheus `.Add()` events.
    *   Strictly aggregates by `process_name` to prevent the time-series cardinality explosions commonly caused by tracking ephemeral PIDs.
4.  **Deployment (Kubernetes):** 
    *   Containerized in a minimal Alpine image.
    *   Deployed via a privileged `DaemonSet` to ensure complete node-level visibility across the cluster.

## Exposed Metrics

The agent exposes a `/metrics` endpoint on port `8080` with the following Prometheus metrics:

| Metric Name | Type | Labels | Description |
| :--- | :--- | :--- | :--- |
| `ebpf_page_cache_accesses_total` | Counter | `process_name` | Total times a process successfully accessed a memory folio in the page cache. |
| `ebpf_page_cache_misses_total` | Counter | `process_name` | Total times the kernel fetched file data from the block layer (disk) for a process. |

## Quick Start (Kubernetes)

**1. Build the container:**
`docker build -t ebpf-node-observer:v1 .`

**2. Load into cluster (if using Kind):**
`kind load docker-image ebpf-node-observer:v1`

**3. Deploy the DaemonSet:**
`kubectl apply -f k8s/daemonset.yaml`

**4. Verify Telemetry:**
`kubectl port-forward -n kube-system ds/ebpf-node-observer 8080:8080 &`
`curl http://127.0.0.1:8080/metrics | grep ebpf`

## Technical Trade-offs & Limitations
*   **O_DIRECT Bypasses:** Applications utilizing Direct I/O (like certain SQL databases) bypass the VFS page cache entirely and will not trigger these specific folio probes.
*   **Readahead Skew:** The Linux readahead engine may preemptively trigger `filemap_add_folio` (misses) for data it anticipates the application will need, temporarily skewing the immediate hit/miss ratio for a given process.
