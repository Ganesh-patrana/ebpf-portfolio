# Phase 3: Kubernetes-Enriched eBPF Exporter
This project couples kernel-level tracing with Kubernetes metadata. It attaches an eBPF kprobe (`mark_page_accessed`) to count page cache hits per process in an eBPF hash map, then uses Go (`client-go`) to map raw PIDs to active Kubernetes Pods and Namespaces.
