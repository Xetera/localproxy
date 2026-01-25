package envoy

import (
	"net/http"
	"strings"

	"github.com/prometheus/common/expfmt"
)

func scrapeEnvoyStats(adminURL string, filter string) (map[string]float64, error) {
	resp, err := http.Get(adminURL + "/stats?format=prometheus")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	parser := expfmt.TextParser{}
	families, err := parser.TextToMetricFamilies(resp.Body)
	if err != nil {
		return nil, err
	}

	result := make(map[string]float64)
	for name, family := range families {
		if filter != "" && !strings.Contains(name, filter) {
			continue
		}
		for _, m := range family.Metric {
			if m.Counter != nil {
				result[name] = m.Counter.GetValue()
			} else if m.Gauge != nil {
				result[name] = m.Gauge.GetValue()
			}
		}
	}
	return result, nil
}
