package wireguardexporter

import (
	"github.com/prometheus/client_golang/prometheus"
	"golang.zx2c4.com/wireguard/wgctrl"
)

var _ prometheus.Collector = &collector{}

const deviceName = "ns1-wg"

// A collector is a prometheus.Collector for a WireGuard device.
type collector struct {
	PeerReceiveBytes  *prometheus.Desc
	PeerTransmitBytes *prometheus.Desc
	PeerLastHandshake *prometheus.Desc

	client    *wgctrl.Client
	peerNames map[string]string
}

// New constructs a prometheus.Collector using a function to fetch WireGuard
// device information (typically using *wgctrl.Client.Devices).
func New(client *wgctrl.Client, peerNames map[string]string) prometheus.Collector {
	// Permit nil map to mean no peer names configured.
	if peerNames == nil {
		peerNames = make(map[string]string)
	}

	// Per-peer metrics are keyed on both device and public key since a peer
	// can be associated with multiple devices.
	labels := []string{"device", "public_key", "peer_name"}

	return &collector{
		PeerReceiveBytes: prometheus.NewDesc(
			"wireguard_peer_receive_bytes_total",
			"Number of bytes received from a given peer.",
			labels,
			nil,
		),

		PeerTransmitBytes: prometheus.NewDesc(
			"wireguard_peer_transmit_bytes_total",
			"Number of bytes transmitted to a given peer.",
			labels,
			nil,
		),

		PeerLastHandshake: prometheus.NewDesc(
			"wireguard_peer_last_handshake_seconds",
			"UNIX timestamp for the last handshake with a given peer.",
			labels,
			nil,
		),

		client:    client,
		peerNames: peerNames,
	}
}

// Describe implements prometheus.Collector.
func (c *collector) Describe(ch chan<- *prometheus.Desc) {
	ds := []*prometheus.Desc{
		c.PeerReceiveBytes,
		c.PeerTransmitBytes,
		c.PeerLastHandshake,
	}

	for _, d := range ds {
		ch <- d
	}
}

// Collect implements prometheus.Collector.
func (c *collector) Collect(ch chan<- prometheus.Metric) {
	device, err := c.client.Device(deviceName)
	if err != nil {
		ch <- prometheus.NewInvalidMetric(c.PeerReceiveBytes, err)
		ch <- prometheus.NewInvalidMetric(c.PeerTransmitBytes, err)
		ch <- prometheus.NewInvalidMetric(c.PeerLastHandshake, err)
	}
	for _, peer := range device.Peers {
		publicKey := peer.PublicKey.String()
		labels := []string{device.Name, publicKey, c.peerNames[publicKey]}
		ch <- prometheus.MustNewConstMetric(
			c.PeerReceiveBytes,
			prometheus.CounterValue,
			float64(peer.ReceiveBytes),
			labels...,
		)

		ch <- prometheus.MustNewConstMetric(
			c.PeerTransmitBytes,
			prometheus.CounterValue,
			float64(peer.TransmitBytes),
			labels...,
		)

		// Expose last handshake of 0 unless a last handshake time is set.
		var last float64
		if !peer.LastHandshakeTime.IsZero() {
			last = float64(peer.LastHandshakeTime.Unix())
		}

		ch <- prometheus.MustNewConstMetric(
			c.PeerLastHandshake,
			prometheus.GaugeValue,
			last,
			labels...,
		)
	}
}
