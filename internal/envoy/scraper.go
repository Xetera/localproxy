package envoy

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"
)

type ClusterStats struct {
	Name                 string
	TCPBytesReceived     uint64
	TCPBytesSent         uint64
	TCPBytesReceivedRate float64
	TCPBytesSentRate     float64
	LastTrafficReceived  time.Time
	HTTPRequestsTotal    uint64
	HTTPRequestsRate     float64
	HTTP2xx              uint64
	HTTP4xx              uint64
	HTTP5xx              uint64
	HTTP1Connections     uint64
	HTTP2Connections     uint64
	HTTP3Connections     uint64
	ActiveConnections    uint64
	ConnectionsTotal     uint64
	DisconnectsLocal     uint64
	DisconnectsRemote    uint64
}

type GlobalStats struct {
	DownstreamHTTP1 uint64
	DownstreamHTTP2 uint64
	DownstreamHTTP3 uint64
}

type StatsScraper struct {
	adminURL     string
	interval     time.Duration
	ctx          context.Context
	cancel       context.CancelFunc
	mu           sync.RWMutex
	clusters     map[string]*ClusterStats
	globalStats  GlobalStats
	prevScrape   map[string]*ClusterStats
	lastScrapeAt time.Time
}

func NewStatsScraper(adminURL string, interval time.Duration) *StatsScraper {
	ctx, cancel := context.WithCancel(context.Background())
	return &StatsScraper{
		adminURL: adminURL,
		interval: interval,
		ctx:      ctx,
		cancel:   cancel,
		clusters: make(map[string]*ClusterStats),
	}
}

func (s *StatsScraper) Start() {
	go s.loop()
}

func (s *StatsScraper) Stop() {
	s.cancel()
}

func (s *StatsScraper) GetClusterStats() map[string]*ClusterStats {
	s.scrape()
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make(map[string]*ClusterStats, len(s.clusters))
	for k, v := range s.clusters {
		copy := *v
		result[k] = &copy
	}
	return result
}

func (s *StatsScraper) GetGlobalStats() GlobalStats {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.globalStats
}

func (s *StatsScraper) loop() {
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	s.scrape()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			s.scrape()
		}
	}
}

func (s *StatsScraper) scrape() {
	metrics, globalStats, err := scrapeEnvoyStats(s.adminURL)
	if err != nil {
		return
	}

	now := time.Now()
	clusters := make(map[string]*ClusterStats)

	for _, m := range metrics {
		clusterName := m.Labels["envoy_cluster_name"]
		if clusterName == "" {
			continue
		}

		stats, ok := clusters[clusterName]
		if !ok {
			stats = &ClusterStats{Name: clusterName}
			clusters[clusterName] = stats
		}

		val := uint64(m.Value)
		switch m.Name {
		case "envoy_cluster_upstream_cx_rx_bytes_total":
			stats.TCPBytesReceived = val
		case "envoy_cluster_upstream_cx_tx_bytes_total":
			stats.TCPBytesSent = val
		case "envoy_cluster_upstream_rq_total":
			stats.HTTPRequestsTotal = val
		case "envoy_cluster_upstream_rq_xx":
			code := m.Labels["envoy_response_code_class"]
			switch code {
			case "2":
				stats.HTTP2xx = val
			case "4":
				stats.HTTP4xx = val
			case "5":
				stats.HTTP5xx = val
			}
		case "envoy_cluster_upstream_cx_active":
			stats.ActiveConnections = val
		case "envoy_cluster_upstream_cx_total":
			stats.ConnectionsTotal = val
		case "envoy_cluster_upstream_cx_destroy_local":
			stats.DisconnectsLocal = val
		case "envoy_cluster_upstream_cx_destroy_remote":
			stats.DisconnectsRemote = val
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.prevScrape != nil && !s.lastScrapeAt.IsZero() {
		elapsed := now.Sub(s.lastScrapeAt).Seconds()
		if elapsed > 0 {
			for name, curr := range clusters {
				if prev, ok := s.prevScrape[name]; ok {
					curr.TCPBytesReceivedRate = float64(curr.TCPBytesReceived-prev.TCPBytesReceived) / elapsed
					curr.TCPBytesSentRate = float64(curr.TCPBytesSent-prev.TCPBytesSent) / elapsed
					curr.HTTPRequestsRate = float64(curr.HTTPRequestsTotal-prev.HTTPRequestsTotal) / elapsed

					if curr.TCPBytesReceived > prev.TCPBytesReceived {
						curr.LastTrafficReceived = now
					} else if !prev.LastTrafficReceived.IsZero() {
						curr.LastTrafficReceived = prev.LastTrafficReceived
					}
				}
			}
		}
	}

	s.prevScrape = s.clusters
	s.clusters = clusters
	s.globalStats = globalStats
	s.lastScrapeAt = now
}

type rawMetric struct {
	Name   string
	Labels map[string]string
	Value  float64
}

func scrapeEnvoyStats(adminURL string) ([]rawMetric, GlobalStats, error) {
	resp, err := http.Get(adminURL + "/stats?format=prometheus")
	if err != nil {
		return nil, GlobalStats{}, err
	}
	defer resp.Body.Close()

	parser := expfmt.NewTextParser(model.UTF8Validation)
	families, err := parser.TextToMetricFamilies(resp.Body)
	if err != nil {
		return nil, GlobalStats{}, err
	}

	var result []rawMetric
	var global GlobalStats

	for name, family := range families {
		if strings.HasPrefix(name, "envoy_cluster_") {
			for _, m := range family.Metric {
				var value float64
				if m.Counter != nil {
					value = m.Counter.GetValue()
				} else if m.Gauge != nil {
					value = m.Gauge.GetValue()
				} else {
					continue
				}

				labels := make(map[string]string)
				for _, lp := range m.Label {
					labels[lp.GetName()] = lp.GetValue()
				}

				result = append(result, rawMetric{
					Name:   name,
					Labels: labels,
					Value:  value,
				})
			}
		}

		switch name {
		case "envoy_http_downstream_cx_http1_total", "envoy_http_downstream_cx_http2_total", "envoy_http_downstream_cx_http3_total":
			for _, m := range family.Metric {
				if m.Counter == nil {
					continue
				}
				val := uint64(m.Counter.GetValue())
				for _, lp := range m.Label {
					if lp.GetName() == "envoy_http_conn_manager_prefix" {
						prefix := lp.GetValue()
						if prefix == "https_ingress" || prefix == "http_ingress" || prefix == "http3_ingress" {
							switch name {
							case "envoy_http_downstream_cx_http1_total":
								global.DownstreamHTTP1 += val
							case "envoy_http_downstream_cx_http2_total":
								global.DownstreamHTTP2 += val
							case "envoy_http_downstream_cx_http3_total":
								global.DownstreamHTTP3 += val
							}
						}
					}
				}
			}
		}
	}
	return result, global, nil
}
