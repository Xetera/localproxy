package proxy

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/reverseproxy"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
)

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

type certInfo struct {
	tag      string
	certPath string
	keyPath  string
	sniNames []string
}

func BuildCaddyConfig(routes []Route, httpsRedirect bool) (*caddyhttp.App, *caddytls.TLS) {
	var httpsRoutes caddyhttp.RouteList
	var httpRoutes caddyhttp.RouteList
	certInfos := make(map[string]*certInfo)

	for _, r := range routes {
		upstream := &reverseproxy.Handler{
			Upstreams: reverseproxy.UpstreamPool{
				&reverseproxy.Upstream{Dial: r.Endpoint.String()},
			},
		}

		var hosts caddyhttp.MatchHost
		var sniNames []string
		if r.Subdomain == "" {
			hosts = caddyhttp.MatchHost{"localhost", "proxy.localhost", "proxy.internal"}
			sniNames = []string{"localhost", "proxy.localhost", "proxy.internal"}
		} else {
			hosts = caddyhttp.MatchHost{
				r.Subdomain + ".localhost",
				r.Subdomain + ".internal",
			}
			sniNames = []string{
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

		if r.CertPath != "" && r.KeyPath != "" {
			if existing, ok := certInfos[tag]; ok {
				existing.sniNames = append(existing.sniNames, sniNames...)
			} else {
				certInfos[tag] = &certInfo{
					tag:      tag,
					certPath: r.CertPath,
					keyPath:  r.KeyPath,
					sniNames: sniNames,
				}
			}
		}
	}

	var certPairs caddytls.FileLoader
	var connPolicies caddytls.ConnectionPolicies
	for _, info := range certInfos {
		certPairs = append(certPairs, caddytls.CertKeyFilePair{
			Certificate: info.certPath,
			Key:         info.keyPath,
			Tags:        []string{info.tag},
		})
		connPolicies = append(connPolicies, &caddytls.ConnectionPolicy{
			MatchersRaw: caddy.ModuleMap{
				"sni": mustJSON(info.sniNames),
			},
			CertSelection: &caddytls.CustomCertSelectionPolicy{
				AnyTag: []string{info.tag},
			},
		})
	}

	connPolicies = append(connPolicies, &caddytls.ConnectionPolicy{})

	httpsServer := &caddyhttp.Server{
		Listen:          []string{"0.0.0.0:443"},
		TLSConnPolicies: connPolicies,
		Routes:          httpsRoutes,
		AutoHTTPS:       &caddyhttp.AutoHTTPSConfig{Disabled: true},
	}

	var httpServerRoutes caddyhttp.RouteList
	if httpsRedirect {
		httpServerRoutes = caddyhttp.RouteList{
			{
				HandlersRaw: []json.RawMessage{
					mustHTTPHandler("static_response", caddyhttp.StaticResponse{
						StatusCode: "308",
						Headers: http.Header{
							"Location": {"https://{http.request.host}{http.request.uri}"},
						},
						Close: true,
					}),
				},
			},
		}
	} else {
		httpServerRoutes = httpRoutes
	}

	httpServer := &caddyhttp.Server{
		Listen:    []string{"0.0.0.0:80"},
		Routes:    httpServerRoutes,
		AutoHTTPS: &caddyhttp.AutoHTTPSConfig{Disabled: true},
		Protocols: []string{"h1"},
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

func BuildFullCaddyConfig(routes []Route, adminSocket string, httpsRedirect bool, logLevel string) (*caddy.Config, error) {
	httpApp, tlsApp := BuildCaddyConfig(routes, httpsRedirect)

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
						Level:     logLevel,
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
