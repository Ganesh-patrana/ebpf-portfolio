package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf page_cache.c

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

// getContainerID attempts to extract the container ID from a process's cgroup file.
func getContainerID(pid uint32) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return ""
	}
	
	// Scan for containerd or docker signatures in the cgroup path
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
	// 1. Initialize Kubernetes Client
	kubeconfig := filepath.Join(homedir.HomeDir(), ".kube", "config")
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		log.Fatalf("Failed to build K8s config: %v", err)
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Fatalf("Failed to create K8s client: %v", err)
	}

	// 2. Load eBPF Programs
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

	fmt.Println("eBPF K8s Exporter Running. Monitoring page cache hits...")

	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		// Fetch current pods from the cluster
		pods, err := clientset.CoreV1().Pods("").List(context.TODO(), metav1.ListOptions{})
		if err != nil {
			fmt.Printf("Error fetching pods: %v\n", err)
			continue
		}

		// Create a map of Container ID -> Pod Name
		containerToPod := make(map[string]string)
		for _, pod := range pods.Items {
			for _, status := range pod.Status.ContainerStatuses {
				// K8s returns IDs like "containerd://<hex_id>"
				cleanID := strings.TrimPrefix(status.ContainerID, "containerd://")
				containerToPod[cleanID] = pod.Name
			}
		}

		var pid uint32
		var hits uint64
		iter := objs.CacheHits.Iterate()
		
		fmt.Printf("\n--- Page Cache Hits (K8s Enriched) ---\n")
		for iter.Next(&pid, &hits) {
			if hits > 50 {
				cID := getContainerID(pid)
				podName := "Host/System"
				
				// Check if the eBPF container ID matches any running K8s Pod
				for k8sID, name := range containerToPod {
					if cID != "" && strings.Contains(cID, k8sID) {
						podName = name
						break
					}
				}
				fmt.Printf("PID: %-6d | Pod: %-15s | Cache Hits: %d\n", pid, podName, hits)
			}
		}
	}
}
