package envoy

import (
	"context"
	"log"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"
)

type Metric struct {
	Name   string
	Labels map[string]string
	Value  float64
}

func (m Metric) String() string {
	if len(m.Labels) == 0 {
		return m.Name
	}
	pairs := make([]string, 0, len(m.Labels))
	for k, v := range m.Labels {
		pairs = append(pairs, k+"="+v)
	}
	sort.Strings(pairs)
	return m.Name + "{" + strings.Join(pairs, ",") + "}"
}

type StatsScraper struct {
	adminURL string
	filter   string
	interval time.Duration
	ctx      context.Context
	cancel   context.CancelFunc
}

func NewStatsScraper(adminURL, filter string, interval time.Duration) *StatsScraper {
	ctx, cancel := context.WithCancel(context.Background())
	return &StatsScraper{
		adminURL: adminURL,
		filter:   filter,
		interval: interval,
		ctx:      ctx,
		cancel:   cancel,
	}
}

func (s *StatsScraper) Start() {
	go s.loop()
}

func (s *StatsScraper) Stop() {
	s.cancel()
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
	metrics, err := scrapeEnvoyStats(s.adminURL, s.filter)
	if err != nil {
		log.Printf("stats scraper: failed to scrape: %v", err)
		return
	}
	for _, m := range metrics {
		log.Printf("stats: %s = %f", m.String(), m.Value)
	}
}

func scrapeEnvoyStats(adminURL string, filter string) ([]Metric, error) {
	resp, err := http.Get(adminURL + "/stats?format=prometheus")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	parser := expfmt.NewTextParser(model.UTF8Validation)
	families, err := parser.TextToMetricFamilies(resp.Body)
	if err != nil {
		return nil, err
	}

	var result []Metric
	for name, family := range families {
		if filter != "" && !strings.Contains(name, filter) {
			continue
		}
		for _, m := range family.Metric {
			var value float64
			if m.Counter != nil {
				value = m.Counter.GetValue()
			} else if m.Gauge != nil {
				value = m.Gauge.GetValue()
			} else if m.Histogram != nil {
				value = float64(m.Histogram.GetSampleCount())
			} else if m.Summary != nil {
				value = float64(m.Summary.GetSampleCount())
			} else {
				continue
			}

			labels := make(map[string]string)
			for _, lp := range m.Label {
				labels[lp.GetName()] = lp.GetValue()
			}

			result = append(result, Metric{
				Name:   name,
				Labels: labels,
				Value:  value,
			})
		}
	}
	return result, nil
}
