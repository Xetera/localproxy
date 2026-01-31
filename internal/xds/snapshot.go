package xds

import (
	_ "embed"
	"fmt"
	"net"
	"time"

	accesslog "github.com/envoyproxy/go-control-plane/envoy/config/accesslog/v3"
	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	endpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	router "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/router/v3"
	tlsinspector "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/listener/tls_inspector/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	tcpproxy "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/tcp_proxy/v3"
	quic "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/quic/v3"
	tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	matcher "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	"github.com/envoyproxy/go-control-plane/pkg/cache/types"
	"github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	"github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

//go:embed 503.html
var error503HTML string

//go:embed 503-dashboard.html
var error503DashboardHTML string

type Protocol string

const (
	ProtocolHTTP Protocol = "http"
	ProtocolTCP  Protocol = "tcp"
)

type Route struct {
	Subdomain string
	Host      string
	Port      int
	TCPPort   int
	Protocol  Protocol
	CertPath  string
	KeyPath   string
}

type SnapshotBuilder struct {
	version int
}

func NewSnapshotBuilder() *SnapshotBuilder {
	return &SnapshotBuilder{version: 0}
}

func (b *SnapshotBuilder) Build(routes []Route, httpsRedirect bool) (*cache.Snapshot, error) {
	b.version++
	versionStr := fmt.Sprintf("%d", b.version)

	var clusters []types.Resource
	var httpsFilterChains []*listener.FilterChain
	var quicFilterChains []*listener.FilterChain
	var httpFilterChains []*listener.FilterChain
	var virtualHosts []*route.VirtualHost
	var secrets []types.Resource

	seenCerts := make(map[string]bool)
	for _, r := range routes {
		if r.CertPath == "" || r.KeyPath == "" {
			continue
		}
		secretName := "cert_" + r.Subdomain
		if r.Subdomain == "" {
			secretName = "cert_localhost"
		}
		if seenCerts[secretName] {
			continue
		}
		seenCerts[secretName] = true
		secrets = append(secrets, &tls.Secret{
			Name: secretName,
			Type: &tls.Secret_TlsCertificate{
				TlsCertificate: &tls.TlsCertificate{
					CertificateChain: &core.DataSource{
						Specifier: &core.DataSource_Filename{Filename: r.CertPath},
					},
					PrivateKey: &core.DataSource{
						Specifier: &core.DataSource_Filename{Filename: r.KeyPath},
					},
				},
			},
		})
	}

	routerFilter, _ := anypb.New(&router.Router{})

	statusCode503Filter := &accesslog.AccessLogFilter{
		FilterSpecifier: &accesslog.AccessLogFilter_StatusCodeFilter{
			StatusCodeFilter: &accesslog.StatusCodeFilter{
				Comparison: &accesslog.ComparisonFilter{
					Op: accesslog.ComparisonFilter_EQ,
					Value: &core.RuntimeUInt32{
						DefaultValue: 503,
						RuntimeKey:   "local_reply_503",
					},
				},
			},
		},
	}

	dashboardHostFilter := &accesslog.AccessLogFilter{
		FilterSpecifier: &accesslog.AccessLogFilter_OrFilter{
			OrFilter: &accesslog.OrFilter{
				Filters: []*accesslog.AccessLogFilter{
					{
						FilterSpecifier: &accesslog.AccessLogFilter_HeaderFilter{
							HeaderFilter: &accesslog.HeaderFilter{
								Header: &route.HeaderMatcher{
									Name: ":authority",
									HeaderMatchSpecifier: &route.HeaderMatcher_StringMatch{
										StringMatch: &matcher.StringMatcher{
											MatchPattern: &matcher.StringMatcher_Exact{Exact: "localhost"},
										},
									},
								},
							},
						},
					},
					{
						FilterSpecifier: &accesslog.AccessLogFilter_HeaderFilter{
							HeaderFilter: &accesslog.HeaderFilter{
								Header: &route.HeaderMatcher{
									Name: ":authority",
									HeaderMatchSpecifier: &route.HeaderMatcher_StringMatch{
										StringMatch: &matcher.StringMatcher{
											MatchPattern: &matcher.StringMatcher_Exact{Exact: "proxy.localhost"},
										},
									},
								},
							},
						},
					},
					{
						FilterSpecifier: &accesslog.AccessLogFilter_HeaderFilter{
							HeaderFilter: &accesslog.HeaderFilter{
								Header: &route.HeaderMatcher{
									Name: ":authority",
									HeaderMatchSpecifier: &route.HeaderMatcher_StringMatch{
										StringMatch: &matcher.StringMatcher{
											MatchPattern: &matcher.StringMatcher_Exact{Exact: "proxy.internal"},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	localReplyConfig := &hcm.LocalReplyConfig{
		Mappers: []*hcm.ResponseMapper{
			{
				Filter: &accesslog.AccessLogFilter{
					FilterSpecifier: &accesslog.AccessLogFilter_AndFilter{
						AndFilter: &accesslog.AndFilter{
							Filters: []*accesslog.AccessLogFilter{
								statusCode503Filter,
								dashboardHostFilter,
							},
						},
					},
				},
				StatusCode: wrapperspb.UInt32(503),
				Body: &core.DataSource{
					Specifier: &core.DataSource_InlineString{InlineString: error503DashboardHTML},
				},
				BodyFormatOverride: &core.SubstitutionFormatString{
					ContentType: "text/html; charset=UTF-8",
					Format: &core.SubstitutionFormatString_TextFormatSource{
						TextFormatSource: &core.DataSource{
							Specifier: &core.DataSource_InlineString{InlineString: "%LOCAL_REPLY_BODY%"},
						},
					},
				},
			},
			{
				Filter: statusCode503Filter,
				StatusCode: wrapperspb.UInt32(503),
				Body: &core.DataSource{
					Specifier: &core.DataSource_InlineString{InlineString: error503HTML},
				},
				BodyFormatOverride: &core.SubstitutionFormatString{
					ContentType: "text/html; charset=UTF-8",
					Format: &core.SubstitutionFormatString_TextFormatSource{
						TextFormatSource: &core.DataSource{
							Specifier: &core.DataSource_InlineString{InlineString: "%LOCAL_REPLY_BODY%"},
						},
					},
				},
			},
		},
	}

	httpsHcm := &hcm.HttpConnectionManager{
		CodecType:             hcm.HttpConnectionManager_AUTO,
		StatPrefix:            "https_ingress",
		StreamIdleTimeout:     durationpb.New(0),
		RequestTimeout:        durationpb.New(0),
		RequestHeadersTimeout: durationpb.New(0),
		LocalReplyConfig:      localReplyConfig,
		RouteSpecifier: &hcm.HttpConnectionManager_Rds{
			Rds: &hcm.Rds{
				ConfigSource: &core.ConfigSource{
					ResourceApiVersion: core.ApiVersion_V3,
					ConfigSourceSpecifier: &core.ConfigSource_Ads{
						Ads: &core.AggregatedConfigSource{},
					},
				},
				RouteConfigName: "local_route",
			},
		},
		HttpFilters: []*hcm.HttpFilter{{
			Name:       "envoy.filters.http.router",
			ConfigType: &hcm.HttpFilter_TypedConfig{TypedConfig: routerFilter},
		}},
	}
	httpsHcmAny, _ := anypb.New(httpsHcm)

	http3Hcm := &hcm.HttpConnectionManager{
		CodecType:             hcm.HttpConnectionManager_HTTP3,
		StatPrefix:            "http3_ingress",
		StreamIdleTimeout:     durationpb.New(0),
		RequestTimeout:        durationpb.New(0),
		RequestHeadersTimeout: durationpb.New(0),
		LocalReplyConfig:      localReplyConfig,
		RouteSpecifier: &hcm.HttpConnectionManager_Rds{
			Rds: &hcm.Rds{
				ConfigSource: &core.ConfigSource{
					ResourceApiVersion: core.ApiVersion_V3,
					ConfigSourceSpecifier: &core.ConfigSource_Ads{
						Ads: &core.AggregatedConfigSource{},
					},
				},
				RouteConfigName: "local_route",
			},
		},
		HttpFilters: []*hcm.HttpFilter{{
			Name:       "envoy.filters.http.router",
			ConfigType: &hcm.HttpFilter_TypedConfig{TypedConfig: routerFilter},
		}},
	}
	http3HcmAny, _ := anypb.New(http3Hcm)

	tcpListenerChains := make(map[int][]*listener.FilterChain)
	tcpListenerNeedsTLS := make(map[int]bool)
	usedPorts := make(map[int]bool)
	seenSubdomains := make(map[string]bool)

	for _, r := range routes {
		if seenSubdomains[r.Subdomain] {
			continue
		}
		seenSubdomains[r.Subdomain] = true
		var clusterName string
		var sniDomains []string
		if r.Subdomain == "" {
			clusterName = "cluster_root"
			sniDomains = []string{"localhost", "proxy.localhost", "proxy.internal"}
		} else {
			clusterName = r.Subdomain
			sniDomains = []string{
				fmt.Sprintf("%s.localhost", r.Subdomain),
				fmt.Sprintf("%s.internal", r.Subdomain),
			}
		}

		secretName := "cert_" + r.Subdomain
		if r.Subdomain == "" {
			secretName = "cert_localhost"
		}

		tlsContext := &tls.DownstreamTlsContext{
			CommonTlsContext: &tls.CommonTlsContext{
				AlpnProtocols: []string{"h2", "postgresql"},
				TlsCertificateSdsSecretConfigs: []*tls.SdsSecretConfig{{
					Name: secretName,
					SdsConfig: &core.ConfigSource{
						ResourceApiVersion: core.ApiVersion_V3,
						ConfigSourceSpecifier: &core.ConfigSource_Ads{
							Ads: &core.AggregatedConfigSource{},
						},
					},
				}},
			},
		}
		tlsContextAny, _ := anypb.New(tlsContext)
		tlsTransportSocket := &core.TransportSocket{
			Name:       "envoy.transport_sockets.tls",
			ConfigType: &core.TransportSocket_TypedConfig{TypedConfig: tlsContextAny},
		}

		quicTlsContext := &tls.DownstreamTlsContext{
			CommonTlsContext: &tls.CommonTlsContext{
				AlpnProtocols: []string{"h3"},
				TlsCertificateSdsSecretConfigs: []*tls.SdsSecretConfig{{
					Name: secretName,
					SdsConfig: &core.ConfigSource{
						ResourceApiVersion: core.ApiVersion_V3,
						ConfigSourceSpecifier: &core.ConfigSource_Ads{
							Ads: &core.AggregatedConfigSource{},
						},
					},
				}},
			},
		}
		quicDownstream := &quic.QuicDownstreamTransport{
			DownstreamTlsContext: quicTlsContext,
		}
		quicDownstreamAny, _ := anypb.New(quicDownstream)
		quicTransportSocket := &core.TransportSocket{
			Name:       "envoy.transport_sockets.quic",
			ConfigType: &core.TransportSocket_TypedConfig{TypedConfig: quicDownstreamAny},
		}

		clusterType := cluster.Cluster_STATIC
		if !isIPAddress(r.Host) {
			clusterType = cluster.Cluster_STRICT_DNS
		}

		clusters = append(clusters, &cluster.Cluster{
			Name:                 clusterName,
			ConnectTimeout:       durationpb.New(5 * time.Second),
			ClusterDiscoveryType: &cluster.Cluster_Type{Type: clusterType},
			LbPolicy:             cluster.Cluster_ROUND_ROBIN,
			LoadAssignment: &endpoint.ClusterLoadAssignment{
				ClusterName: clusterName,
				Endpoints: []*endpoint.LocalityLbEndpoints{{
					LbEndpoints: []*endpoint.LbEndpoint{{
						HostIdentifier: &endpoint.LbEndpoint_Endpoint{
							Endpoint: &endpoint.Endpoint{
								Address: &core.Address{
									Address: &core.Address_SocketAddress{
										SocketAddress: &core.SocketAddress{
											Protocol: core.SocketAddress_TCP,
											Address:  r.Host,
											PortSpecifier: &core.SocketAddress_PortValue{
												PortValue: uint32(r.Port),
											},
										},
									},
								},
							},
						},
					}},
				}},
			},
		})

		if r.Protocol == ProtocolTCP && r.TCPPort > 0 {
			if isPortInUse(r.TCPPort) {
				continue
			}
			tcpProxyConfig := &tcpproxy.TcpProxy{
				StatPrefix: fmt.Sprintf("tcp_%s", r.Subdomain),
				ClusterSpecifier: &tcpproxy.TcpProxy_Cluster{
					Cluster: clusterName,
				},
			}
			tcpProxyAny, _ := anypb.New(tcpProxyConfig)

			if usedPorts[r.TCPPort] {
				tcpListenerNeedsTLS[r.TCPPort] = true
			}

			tcpListenerChains[r.TCPPort] = append(tcpListenerChains[r.TCPPort], &listener.FilterChain{
				FilterChainMatch: &listener.FilterChainMatch{
					ServerNames: sniDomains,
				},
				TransportSocket: tlsTransportSocket,
				Filters: []*listener.Filter{{
					Name:       "envoy.filters.network.tcp_proxy",
					ConfigType: &listener.Filter_TypedConfig{TypedConfig: tcpProxyAny},
				}},
			})
			usedPorts[r.TCPPort] = true
		} else {
			virtualHosts = append(virtualHosts, &route.VirtualHost{
				Name:    fmt.Sprintf("vhost_%s", r.Subdomain),
				Domains: sniDomains,
				Routes: []*route.Route{{
					Match: &route.RouteMatch{
						PathSpecifier: &route.RouteMatch_Prefix{Prefix: "/"},
					},
					Action: &route.Route_Route{
						Route: &route.RouteAction{
							ClusterSpecifier: &route.RouteAction_Cluster{Cluster: clusterName},
						},
					},
				}},
				ResponseHeadersToAdd: []*core.HeaderValueOption{{
					Header: &core.HeaderValue{
						Key:   "alt-svc",
						Value: `h3=":443"; ma=86400`,
					},
				}},
			})

			if r.CertPath != "" && r.KeyPath != "" {
				httpsFilterChains = append(httpsFilterChains, &listener.FilterChain{
					FilterChainMatch: &listener.FilterChainMatch{
						ServerNames: sniDomains,
					},
					TransportSocket: tlsTransportSocket,
					Filters: []*listener.Filter{{
						Name:       "envoy.filters.network.http_connection_manager",
						ConfigType: &listener.Filter_TypedConfig{TypedConfig: httpsHcmAny},
					}},
				})

				quicFilterChains = append(quicFilterChains, &listener.FilterChain{
					FilterChainMatch: &listener.FilterChainMatch{
						ServerNames: sniDomains,
					},
					TransportSocket: quicTransportSocket,
					Filters: []*listener.Filter{{
						Name:       "envoy.filters.network.http_connection_manager",
						ConfigType: &listener.Filter_TypedConfig{TypedConfig: http3HcmAny},
					}},
				})
			}
		}
	}

	var routeConfigs []types.Resource

	virtualHosts = append(virtualHosts, &route.VirtualHost{
		Name:    "vhost_fallback",
		Domains: []string{"*"},
		Routes: []*route.Route{{
			Match: &route.RouteMatch{
				PathSpecifier: &route.RouteMatch_Prefix{Prefix: "/"},
			},
			Action: &route.Route_Route{
				Route: &route.RouteAction{
					ClusterSpecifier: &route.RouteAction_Cluster{Cluster: "cluster_root"},
				},
			},
			RequestHeadersToAdd: []*core.HeaderValueOption{{
				Header: &core.HeaderValue{
					Key:   "X-Forwarded-Host",
					Value: "%REQ(:authority)%",
				},
			}},
		}},
	})

	if len(virtualHosts) > 0 {
		routeConfigs = append(routeConfigs, &route.RouteConfiguration{
			Name:         "local_route",
			VirtualHosts: virtualHosts,
		})

		var httpHcm *hcm.HttpConnectionManager
		if httpsRedirect {
			httpHcm = &hcm.HttpConnectionManager{
				CodecType:             hcm.HttpConnectionManager_AUTO,
				StatPrefix:            "http_ingress",
				StreamIdleTimeout:     durationpb.New(0),
				RequestTimeout:        durationpb.New(0),
				RequestHeadersTimeout: durationpb.New(0),
				RouteSpecifier: &hcm.HttpConnectionManager_RouteConfig{
					RouteConfig: &route.RouteConfiguration{
						Name: "http_redirect_route",
						VirtualHosts: []*route.VirtualHost{{
							Name:    "redirect_all",
							Domains: []string{"*"},
							Routes: []*route.Route{{
								Match: &route.RouteMatch{
									PathSpecifier: &route.RouteMatch_Prefix{Prefix: "/"},
								},
								Action: &route.Route_Redirect{
									Redirect: &route.RedirectAction{
										SchemeRewriteSpecifier: &route.RedirectAction_HttpsRedirect{
											HttpsRedirect: true,
										},
									},
								},
							}},
						}},
					},
				},
				HttpFilters: []*hcm.HttpFilter{{
					Name:       "envoy.filters.http.router",
					ConfigType: &hcm.HttpFilter_TypedConfig{TypedConfig: routerFilter},
				}},
			}
		} else {
			httpHcm = &hcm.HttpConnectionManager{
				CodecType:             hcm.HttpConnectionManager_AUTO,
				StatPrefix:            "http_ingress",
				StreamIdleTimeout:     durationpb.New(0),
				RequestTimeout:        durationpb.New(0),
				RequestHeadersTimeout: durationpb.New(0),
				LocalReplyConfig:      localReplyConfig,
				RouteSpecifier: &hcm.HttpConnectionManager_Rds{
					Rds: &hcm.Rds{
						ConfigSource: &core.ConfigSource{
							ResourceApiVersion: core.ApiVersion_V3,
							ConfigSourceSpecifier: &core.ConfigSource_Ads{
								Ads: &core.AggregatedConfigSource{},
							},
						},
						RouteConfigName: "local_route",
					},
				},
				HttpFilters: []*hcm.HttpFilter{{
					Name:       "envoy.filters.http.router",
					ConfigType: &hcm.HttpFilter_TypedConfig{TypedConfig: routerFilter},
				}},
			}
		}
		httpHcmAny, _ := anypb.New(httpHcm)

		httpFilterChains = append(httpFilterChains, &listener.FilterChain{
			Filters: []*listener.Filter{{
				Name:       "envoy.filters.network.http_connection_manager",
				ConfigType: &listener.Filter_TypedConfig{TypedConfig: httpHcmAny},
			}},
		})
	}

	tlsInspectorAny, _ := anypb.New(&tlsinspector.TlsInspector{})

	var listeners []types.Resource

	if len(httpFilterChains) > 0 {
		listeners = append(listeners, &listener.Listener{
			Name: "http_listener",
			Address: &core.Address{
				Address: &core.Address_SocketAddress{
					SocketAddress: &core.SocketAddress{
						Protocol: core.SocketAddress_TCP,
						Address:  "0.0.0.0",
						PortSpecifier: &core.SocketAddress_PortValue{
							PortValue: 80,
						},
					},
				},
			},
			FilterChains: httpFilterChains,
		})
	}

	if len(httpsFilterChains) > 0 {
		listeners = append(listeners, &listener.Listener{
			Name: "https_listener",
			Address: &core.Address{
				Address: &core.Address_SocketAddress{
					SocketAddress: &core.SocketAddress{
						Protocol: core.SocketAddress_TCP,
						Address:  "0.0.0.0",
						PortSpecifier: &core.SocketAddress_PortValue{
							PortValue: 443,
						},
					},
				},
			},
			ListenerFilters: []*listener.ListenerFilter{{
				Name:       "envoy.filters.listener.tls_inspector",
				ConfigType: &listener.ListenerFilter_TypedConfig{TypedConfig: tlsInspectorAny},
			}},
			FilterChains: httpsFilterChains,
		})

		listeners = append(listeners, &listener.Listener{
			Name: "quic_listener",
			Address: &core.Address{
				Address: &core.Address_SocketAddress{
					SocketAddress: &core.SocketAddress{
						Protocol: core.SocketAddress_UDP,
						Address:  "0.0.0.0",
						PortSpecifier: &core.SocketAddress_PortValue{
							PortValue: 443,
						},
					},
				},
			},
			UdpListenerConfig: &listener.UdpListenerConfig{
				QuicOptions: &listener.QuicProtocolOptions{},
			},
			FilterChains: quicFilterChains,
		})
	}

	for port, chains := range tcpListenerChains {
		tcpListener := &listener.Listener{
			Name: fmt.Sprintf("tcp_listener_%d", port),
			Address: &core.Address{
				Address: &core.Address_SocketAddress{
					SocketAddress: &core.SocketAddress{
						Protocol: core.SocketAddress_TCP,
						Address:  "0.0.0.0",
						PortSpecifier: &core.SocketAddress_PortValue{
							PortValue: uint32(port),
						},
					},
				},
			},
			ListenerFilters: []*listener.ListenerFilter{{
				Name:       "envoy.filters.listener.tls_inspector",
				ConfigType: &listener.ListenerFilter_TypedConfig{TypedConfig: tlsInspectorAny},
			}},
		}

		if tcpListenerNeedsTLS[port] {
			tcpListener.FilterChains = chains
		} else {
			rawChain := &listener.FilterChain{
				Filters: chains[0].Filters,
			}
			tcpListener.FilterChains = append([]*listener.FilterChain{rawChain}, chains...)
		}

		listeners = append(listeners, tcpListener)
	}

	snap, err := cache.NewSnapshot(
		versionStr,
		map[resource.Type][]types.Resource{
			resource.ClusterType:  clusters,
			resource.RouteType:    routeConfigs,
			resource.ListenerType: listeners,
			resource.SecretType:   secrets,
		},
	)
	if err != nil {
		return nil, err
	}

	return snap, nil
}

func isIPAddress(host string) bool {
	return net.ParseIP(host) != nil
}

func isPortInUse(port int) bool {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return true
	}
	listener.Close()
	return false
}
