// Command wireguard_exporter implements a Prometheus exporter for WireGuard
// devices.
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"time"

	wireguardexporter "github.com/cheina97/wireguard_exporter"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.zx2c4.com/wireguard/wgctrl"
)

const deviceName = "ns1-wg"

func main() {
	var (
		metricsAddr = flag.String("metrics.addr", ":9586", "address for WireGuard exporter")
		metricsPath = flag.String("metrics.path", "/metrics", "URL path for surfacing collected metrics")
	)

	flag.Parse()

	client, err := wgctrl.New()
	if err != nil {
		log.Fatalf("failed to open WireGuard control client: %v", err)
	}
	defer client.Close()

	device, err := client.Device(deviceName)
	if err != nil {
		log.Fatalf("failed to find %s device: %v", deviceName, err)
	}

	// Configure the friendly peer names map if the flag is not empty.
	count := 0
	peerNames := make(map[string]string)
	for _, peer := range device.Peers {
		peerNames[peer.PublicKey.String()] = fmt.Sprintf("Cluster-%d", count)
		count++
	}

	// Make Prometheus client aware of our collector.
	c := wireguardexporter.New(client, peerNames)
	prometheus.MustRegister(c)

	// Set up HTTP handler for metrics.
	mux := http.NewServeMux()
	mux.Handle(*metricsPath, promhttp.Handler())

	// Start listening for HTTP connections.
	log.Printf("starting WireGuard exporter on %q", *metricsAddr)
	server := http.Server{
		Addr:         *metricsAddr,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("cannot start WireGuard exporter: %s", err)
	}
}
