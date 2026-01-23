package xds

import (
	"fmt"
	"os"
	"time"

	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	endpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	router "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/router/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	"github.com/envoyproxy/go-control-plane/pkg/cache/types"
	"github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	"github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
)

type Route struct {
	Subdomain string
	Host      string
	Port      int
}

type SnapshotBuilder struct {
	version int
}

func NewSnapshotBuilder() *SnapshotBuilder {
	return &SnapshotBuilder{version: 0}
}

func (b *SnapshotBuilder) Build(routes []Route, certPath, keyPath string) (*cache.Snapshot, error) {
	b.version++
	versionStr := fmt.Sprintf("%d", b.version)

	var clusters []types.Resource
	var endpoints []types.Resource
	var virtualHosts []*route.VirtualHost

	for _, r := range routes {
		clusterName := fmt.Sprintf("cluster_%s", r.Subdomain)

		clusters = append(clusters, &cluster.Cluster{
			Name:                 clusterName,
			ConnectTimeout:       durationpb.New(5 * time.Second),
			ClusterDiscoveryType: &cluster.Cluster_Type{Type: cluster.Cluster_STRICT_DNS},
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

		virtualHosts = append(virtualHosts, &route.VirtualHost{
			Name:    fmt.Sprintf("vhost_%s", r.Subdomain),
			Domains: []string{fmt.Sprintf("%s.localhost", r.Subdomain)},
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
		})
	}

	routeConfig := &route.RouteConfiguration{
		Name:         "local_route",
		VirtualHosts: virtualHosts,
	}

	routeConfigAny, _ := anypb.New(routeConfig)
	routerFilter, _ := anypb.New(&router.Router{})

	httpConnMgr := &hcm.HttpConnectionManager{
		CodecType:  hcm.HttpConnectionManager_AUTO,
		StatPrefix: "ingress_http",
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

	httpConnMgrAny, _ := anypb.New(httpConnMgr)

	var listeners []types.Resource

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
		FilterChains: []*listener.FilterChain{{
			Filters: []*listener.Filter{{
				Name:       "envoy.filters.network.http_connection_manager",
				ConfigType: &listener.Filter_TypedConfig{TypedConfig: httpConnMgrAny},
			}},
		}},
	})

	var secrets []types.Resource

	if certPath != "" && keyPath != "" {
		certData, err := os.ReadFile(certPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read cert: %w", err)
		}
		keyData, err := os.ReadFile(keyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read key: %w", err)
		}

		secrets = append(secrets, &tls.Secret{
			Name: "localhost_cert",
			Type: &tls.Secret_TlsCertificate{
				TlsCertificate: &tls.TlsCertificate{
					CertificateChain: &core.DataSource{
						Specifier: &core.DataSource_InlineBytes{InlineBytes: certData},
					},
					PrivateKey: &core.DataSource{
						Specifier: &core.DataSource_InlineBytes{InlineBytes: keyData},
					},
				},
			},
		})

		tlsContext := &tls.DownstreamTlsContext{
			CommonTlsContext: &tls.CommonTlsContext{
				TlsCertificateSdsSecretConfigs: []*tls.SdsSecretConfig{{
					Name: "localhost_cert",
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
			FilterChains: []*listener.FilterChain{{
				TransportSocket: &core.TransportSocket{
					Name:       "envoy.transport_sockets.tls",
					ConfigType: &core.TransportSocket_TypedConfig{TypedConfig: tlsContextAny},
				},
				Filters: []*listener.Filter{{
					Name:       "envoy.filters.network.http_connection_manager",
					ConfigType: &listener.Filter_TypedConfig{TypedConfig: httpConnMgrAny},
				}},
			}},
		})
	}

	snap, err := cache.NewSnapshot(
		versionStr,
		map[resource.Type][]types.Resource{
			resource.ClusterType:  clusters,
			resource.EndpointType: endpoints,
			resource.RouteType:    {routeConfigAny},
			resource.ListenerType: listeners,
			resource.SecretType:   secrets,
		},
	)
	if err != nil {
		return nil, err
	}

	return snap, nil
}
