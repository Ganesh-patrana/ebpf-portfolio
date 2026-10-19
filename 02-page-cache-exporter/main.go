package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf page_cache.c

import (
	"fmt"
	"log"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	// 1. Allow the process to lock memory for eBPF resources (Required for older kernels)
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock: %v", err)
	}

	// 2. Load the auto-generated pre-compiled programs and maps into the kernel
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("Failed to load eBPF objects: %v", err)
	}
	defer objs.Close()

	// 3. Attach the eBPF program to the kernel function
	kp, err := link.Kprobe("mark_page_accessed", objs.CountCacheHits, nil)
	if err != nil {
		log.Fatalf("Failed to attach kprobe: %v", err)
	}
	defer kp.Close()

	fmt.Println("Successfully hooked into the kernel! Monitoring page cache hits (Ctrl+C to exit)...")

	// 4. Poll the eBPF map every 3 seconds
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		var pid uint32
		var hits uint64
		iter := objs.CacheHits.Iterate()
		
		fmt.Printf("\n--- Top Page Cache Hits by PID ---\n")
		// Iterate through the eBPF map populated by the kernel
		for iter.Next(&pid, &hits) {
			if hits > 50 { // Filter out low-noise processes for readability
				fmt.Printf("PID: %-6d | Cache Hits: %d\n", pid, hits)
			}
		}
	}
}
