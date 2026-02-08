package caddy

import (
	"encoding/json"
	"fmt"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/reverseproxy"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
)

type Route struct {
	Subdomain string
	TargetIP  string
	TargetPort int
	CertPath  string
	KeyPath   string
}

func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

func mustHTTPHandler(name string, h any) json.RawMessage {
	b, err := json.Marshal(h)
	if err != nil {
		panic(err)
	}
	var m map[string]any
	json.Unmarshal(b, &m)
	m["handler"] = name
	out, _ := json.Marshal(m)
	return out
}

func BuildHTTPConfig(routes []Route) (*caddyhttp.App, *caddytls.TLS) {
	var httpsRoutes caddyhttp.RouteList
	var httpRoutes caddyhttp.RouteList
	var certPairs caddytls.FileLoader
	certTags := make(map[string]bool)

	for _, r := range routes {
		upstream := &reverseproxy.Handler{
			Upstreams: reverseproxy.UpstreamPool{
				&reverseproxy.Upstream{Dial: fmt.Sprintf("%s:%d", r.TargetIP, r.TargetPort)},
			},
		}

		var hosts caddyhttp.MatchHost
		if r.Subdomain == "" {
			hosts = caddyhttp.MatchHost{"localhost", "proxy.localhost", "proxy.internal"}
		} else {
			hosts = caddyhttp.MatchHost{
				r.Subdomain + ".localhost",
				r.Subdomain + ".internal",
			}
		}

		route := caddyhttp.Route{
			MatcherSetsRaw: caddyhttp.RawMatcherSets{
				caddy.ModuleMap{"host": mustJSON(hosts)},
			},
			HandlersRaw: []json.RawMessage{
				mustHTTPHandler("reverse_proxy", upstream),
			},
		}

		httpsRoutes = append(httpsRoutes, route)
		httpRoutes = append(httpRoutes, route)

		tag := r.Subdomain
		if tag == "" {
			tag = "localhost"
		}

		if !certTags[tag] && r.CertPath != "" && r.KeyPath != "" {
			certPairs = append(certPairs, caddytls.CertKeyFilePair{
				Certificate: r.CertPath,
				Key:         r.KeyPath,
				Tags:        []string{tag},
			})
			certTags[tag] = true
		}
	}

	var connPolicies caddytls.ConnectionPolicies
	for tag := range certTags {
		connPolicies = append(connPolicies, &caddytls.ConnectionPolicy{
			CertSelection: &caddytls.CustomCertSelectionPolicy{
				AnyTag: []string{tag},
			},
		})
	}

	httpsServer := &caddyhttp.Server{
		Listen:          []string{":443"},
		TLSConnPolicies: connPolicies,
		Routes:          httpsRoutes,
	}

	httpServer := &caddyhttp.Server{
		Listen: []string{":80"},
		Routes: httpRoutes,
	}

	httpApp := &caddyhttp.App{
		Servers: map[string]*caddyhttp.Server{
			"https": httpsServer,
			"http":  httpServer,
		},
	}

	tlsApp := &caddytls.TLS{
		CertificatesRaw: caddy.ModuleMap{
			"load_files": mustJSON(certPairs),
		},
	}

	return httpApp, tlsApp
}

func BuildConfig(routes []Route, adminSocket string) (*caddy.Config, error) {
	httpApp, tlsApp := BuildHTTPConfig(routes)

	httpJSON, err := json.Marshal(httpApp)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal http config: %w", err)
	}

	tlsJSON, err := json.Marshal(tlsApp)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal tls config: %w", err)
	}

	cfg := &caddy.Config{
		Logging: &caddy.Logging{
			Logs: map[string]*caddy.CustomLog{
				"default": {
					BaseLog: caddy.BaseLog{
						WriterRaw: json.RawMessage(`{"output": "stdout"}`),
						Level:     "INFO",
					},
				},
			},
		},
		Admin: &caddy.AdminConfig{
			Listen: "unix/" + adminSocket,
		},
		AppsRaw: caddy.ModuleMap{
			"http": httpJSON,
			"tls":  tlsJSON,
		},
	}

	return cfg, nil
}
