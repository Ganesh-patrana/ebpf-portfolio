package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type cache_stat bpf page_cache_obs.bpf.c -- -I/usr/include/bpf -O2 -g

import (
	"bytes"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Define Prometheus Metrics
var (
	accessesTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ebpf_page_cache_accesses_total",
			Help: "Total number of page cache accesses (hits + misses)",
		},
		[]string{"process_name"}, // Our safe cardinality label
	)
	missesTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ebpf_page_cache_misses_total",
			Help: "Total number of page cache misses (disk reads)",
		},
		[]string{"process_name"},
	)
)

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock: %v", err)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("Failed to load eBPF objects: %v", err)
	}
	defer objs.Close()

	kprobeAccess, err := link.Kprobe("folio_mark_accessed", objs.TraceFolioAccess, nil)
	if err != nil {
		log.Fatalf("Failed to attach kprobe (folio_mark_accessed): %v", err)
	}
	defer kprobeAccess.Close()

	kprobeMiss, err := link.Kprobe("filemap_add_folio", objs.TraceFolioMiss, nil)
	if err != nil {
		log.Fatalf("Failed to attach kprobe (filemap_add_folio): %v", err)
	}
	defer kprobeMiss.Close()

	// Start Prometheus HTTP server in a background goroutine
	http.Handle("/metrics", promhttp.Handler())
	go func() {
		log.Println("Starting Prometheus exporter on :8080/metrics")
		if err := http.ListenAndServe(":8080", nil); err != nil {
			log.Fatalf("HTTP server failed: %v", err)
		}
	}()

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	// State maps to track the previous values we read from the kernel
	lastAccesses := make(map[string]uint64)
	lastMisses := make(map[string]uint64)

	for {
		select {
		case <-ticker.C:
			var key [16]byte
			var val bpfCacheStat
			iterator := objs.CacheStats.Iterate()

			for iterator.Next(&key, &val) {
				processName := string(bytes.TrimRight(key[:], "\x00"))

				// Calculate the delta (current kernel value - last known value)
				deltaAccess := val.Accesses - lastAccesses[processName]
				deltaMiss := val.Misses - lastMisses[processName]

				// Add the delta to the Prometheus counters
				if deltaAccess > 0 {
					accessesTotal.WithLabelValues(processName).Add(float64(deltaAccess))
					lastAccesses[processName] = val.Accesses
				}
				if deltaMiss > 0 {
					missesTotal.WithLabelValues(processName).Add(float64(deltaMiss))
					lastMisses[processName] = val.Misses
				}
			}

			if err := iterator.Err(); err != nil {
				log.Printf("Error iterating map: %v", err)
			}

		case <-stopper:
			log.Println("Shutting down eBPF observer...")
			return
		}
	}
}
