package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf page_cache.c

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

var (
	pageCacheHits = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ebpf_page_cache_hits_total",
			Help: "Total number of page cache hits captured via eBPF kprobe",
		},
		[]string{"pid", "pod_name"},
	)
)

func init() {
	prometheus.MustRegister(pageCacheHits)
}

func getContainerID(pid uint32) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.Contains(line, "containerd-") || strings.Contains(line, "docker-") || strings.Contains(line, "cri-containerd:") {
			parts := strings.Split(line, "/")
			if len(parts) > 0 {
				id := parts[len(parts)-1]
				id = strings.TrimPrefix(id, "docker-")
				id = strings.TrimPrefix(id, "cri-containerd:")
				id = strings.TrimSuffix(id, ".scope")
				return id
			}
		}
	}
	return ""
}

func main() {
	kubeconfig := filepath.Join(homedir.HomeDir(), ".kube", "config")
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		log.Fatalf("Failed to build K8s config: %v", err)
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Fatalf("Failed to create K8s client: %v", err)
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock: %v", err)
	}
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("Failed to load eBPF objects: %v", err)
	}
	defer objs.Close()

	kp, err := link.Kprobe("mark_page_accessed", objs.CountCacheHits, nil)
	if err != nil {
		log.Fatalf("Failed to attach kprobe: %v", err)
	}
	defer kp.Close()

	// Start Prometheus metrics endpoint in the background
	go func() {
		http.Handle("/metrics", promhttp.Handler())
		log.Println("Serving Prometheus metrics at :2112/metrics")
		if err := http.ListenAndServe(":2112", nil); err != nil {
			log.Fatalf("Metrics server error: %v", err)
		}
	}()

	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	// Track previous hits per PID to compute delta additions to Prometheus Counter
	lastHits := make(map[uint32]uint64)

	for range ticker.C {
		pods, err := clientset.CoreV1().Pods("").List(context.TODO(), metav1.ListOptions{})
		if err != nil {
			continue
		}

		containerToPod := make(map[string]string)
		for _, pod := range pods.Items {
			for _, status := range pod.Status.ContainerStatuses {
				cleanID := strings.TrimPrefix(status.ContainerID, "containerd://")
				containerToPod[cleanID] = pod.Name
			}
		}

		var pid uint32
		var hits uint64
		iter := objs.CacheHits.Iterate()

		for iter.Next(&pid, &hits) {
			if hits > lastHits[pid] {
				delta := hits - lastHits[pid]
				lastHits[pid] = hits

				cID := getContainerID(pid)
				podName := "system"
				for k8sID, name := range containerToPod {
					if cID != "" && strings.Contains(cID, k8sID) {
						podName = name
						break
					}
				}

				pageCacheHits.WithLabelValues(fmt.Sprintf("%d", pid), podName).Add(float64(delta))
			}
		}
	}
}
