package proxy

import (
	"encoding/json"
	"fmt"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
	"github.com/mholt/caddy-l4/layer4"
	"github.com/mholt/caddy-l4/modules/l4proxy"
	"github.com/mholt/caddy-l4/modules/l4tls"
)

func mustL4Handler(name string, h any, alpn []string) json.RawMessage {
	b, err := json.Marshal(h)
	if err != nil {
		panic(err)
	}
	var m map[string]any
	json.Unmarshal(b, &m)
	m["handler"] = name
	if alpn != nil {
		injectALPN(m, alpn)
	}
	out, _ := json.Marshal(m)
	return out
}

var l4ALPN = []string{"postgresql"}

func injectALPN(m map[string]any, alpn []string) {
	policies, ok := m["connection_policies"].([]any)
	if !ok {
		return
	}
	for _, p := range policies {
		if pol, ok := p.(map[string]any); ok {
			pol["alpn"] = alpn
		}
	}
}

func BuildL4App(routes []Route) *layer4.App {
	type portRoutes struct {
		routes []Route
	}
	byPort := make(map[int]*portRoutes)

	for _, r := range routes {
		if r.TCPPort <= 0 {
			continue
		}
		if byPort[r.TCPPort] == nil {
			byPort[r.TCPPort] = &portRoutes{}
		}
		byPort[r.TCPPort].routes = append(byPort[r.TCPPort].routes, r)
	}

	if len(byPort) == 0 {
		return nil
	}

	servers := make(map[string]*layer4.Server)

	for port, pr := range byPort {
		var l4Routes layer4.RouteList

		for _, r := range pr.routes {
			proxyHandler := &l4proxy.Handler{
				Upstreams: l4proxy.UpstreamPool{
					&l4proxy.Upstream{
						Dial: []string{r.Endpoint.String()},
					},
				},
			}

			tag := r.Subdomain
			if tag == "" {
				tag = "localhost"
			}

			sniNames := []string{
				r.Subdomain + ".localhost",
				r.Subdomain + ".internal",
				r.Subdomain,
			}
			sniJSON, _ := json.Marshal(map[string][]string{"sni": sniNames})

			tlsHandler := &l4tls.Handler{
				ConnectionPolicies: caddytls.ConnectionPolicies{
					&caddytls.ConnectionPolicy{
						CertSelection: &caddytls.CustomCertSelectionPolicy{
							AnyTag: []string{tag},
						},
					},
				},
			}

			tlsRoute := &layer4.Route{
				MatcherSetsRaw: []caddy.ModuleMap{
					{"tls": sniJSON},
				},
				HandlersRaw: []json.RawMessage{
					mustL4Handler("tls", tlsHandler, l4ALPN),
					mustL4Handler("proxy", proxyHandler, nil),
				},
			}

			l4Routes = append(l4Routes, tlsRoute)
		}

		tlsFallbackProxy := &l4proxy.Handler{
			Upstreams: l4proxy.UpstreamPool{
				&l4proxy.Upstream{
					Dial: []string{pr.routes[0].Endpoint.String()},
				},
			},
		}
		tlsFallbackHandler := &l4tls.Handler{
			ConnectionPolicies: caddytls.ConnectionPolicies{
				&caddytls.ConnectionPolicy{
					CertSelection: &caddytls.CustomCertSelectionPolicy{
						AnyTag: []string{func() string {
							tag := pr.routes[0].Subdomain
							if tag == "" {
								return "localhost"
							}
							return tag
						}()},
					},
				},
			},
		}
		tlsFallbackRoute := &layer4.Route{
			MatcherSetsRaw: []caddy.ModuleMap{
				{"tls": json.RawMessage(`{}`)},
			},
			HandlersRaw: []json.RawMessage{
				mustL4Handler("tls", tlsFallbackHandler, l4ALPN),
				mustL4Handler("proxy", tlsFallbackProxy, nil),
			},
		}
		l4Routes = append(l4Routes, tlsFallbackRoute)

		plaintextProxy := &l4proxy.Handler{
			Upstreams: l4proxy.UpstreamPool{
				&l4proxy.Upstream{
					Dial: []string{pr.routes[0].Endpoint.String()},
				},
			},
		}
		plaintextRoute := &layer4.Route{
			HandlersRaw: []json.RawMessage{
				mustL4Handler("proxy", plaintextProxy, nil),
			},
		}
		l4Routes = append(l4Routes, plaintextRoute)

		servers[fmt.Sprintf("tcp_%d", port)] = &layer4.Server{
			Listen: []string{fmt.Sprintf("0.0.0.0:%d", port)},
			Routes: l4Routes,
		}
	}

	return &layer4.App{Servers: servers}
}
