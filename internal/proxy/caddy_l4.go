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

func mustL4Handler(name string, h any) json.RawMessage {
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
					mustL4Handler("tls", tlsHandler),
					mustL4Handler("proxy", proxyHandler),
				},
			}

			l4Routes = append(l4Routes, tlsRoute)
		}

		fallbackProxy := &l4proxy.Handler{
			Upstreams: l4proxy.UpstreamPool{
				&l4proxy.Upstream{
					Dial: []string{pr.routes[0].Endpoint.String()},
				},
			},
		}
		fallbackRoute := &layer4.Route{
			HandlersRaw: []json.RawMessage{
				mustL4Handler("proxy", fallbackProxy),
			},
		}
		l4Routes = append(l4Routes, fallbackRoute)

		servers[fmt.Sprintf("tcp_%d", port)] = &layer4.Server{
			Listen: []string{fmt.Sprintf("tcp/:%d", port)},
			Routes: l4Routes,
		}
	}

	return &layer4.App{Servers: servers}
}
