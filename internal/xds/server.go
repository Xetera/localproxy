package xds

import (
	"context"
	"fmt"
	"net"

	clusterservice "github.com/envoyproxy/go-control-plane/envoy/service/cluster/v3"
	discoverygrpc "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	endpointservice "github.com/envoyproxy/go-control-plane/envoy/service/endpoint/v3"
	listenerservice "github.com/envoyproxy/go-control-plane/envoy/service/listener/v3"
	routeservice "github.com/envoyproxy/go-control-plane/envoy/service/route/v3"
	secretservice "github.com/envoyproxy/go-control-plane/envoy/service/secret/v3"
	"github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	"github.com/envoyproxy/go-control-plane/pkg/log"
	"github.com/envoyproxy/go-control-plane/pkg/server/v3"
	"google.golang.org/grpc"
)

const nodeID = "localproxy-envoy"

type Server struct {
	grpcServer    *grpc.Server
	xdsServer     server.Server
	cache         cache.SnapshotCache
	snapshot      *SnapshotBuilder
	httpsRedirect bool
}

func NewServer() *Server {
	log := log.NewDefaultLogger()
	snapshotCache := cache.NewSnapshotCache(false, cache.IDHash{}, log)
	srv := server.NewServer(context.Background(), snapshotCache, nil)

	s := &Server{
		grpcServer: grpc.NewServer(),
		xdsServer:  srv,
		cache:      snapshotCache,
		snapshot:   NewSnapshotBuilder(),
	}

	discoverygrpc.RegisterAggregatedDiscoveryServiceServer(s.grpcServer, srv)
	clusterservice.RegisterClusterDiscoveryServiceServer(s.grpcServer, srv)
	endpointservice.RegisterEndpointDiscoveryServiceServer(s.grpcServer, srv)
	listenerservice.RegisterListenerDiscoveryServiceServer(s.grpcServer, srv)
	routeservice.RegisterRouteDiscoveryServiceServer(s.grpcServer, srv)
	secretservice.RegisterSecretDiscoveryServiceServer(s.grpcServer, srv)

	return s
}

func (s *Server) Start(addr string) error {
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}
	go s.grpcServer.Serve(lis)
	return nil
}

func (s *Server) Stop() {
	s.grpcServer.GracefulStop()
}

func (s *Server) SetHTTPSRedirect(enabled bool) {
	s.httpsRedirect = enabled
}

func (s *Server) UpdateSnapshot(routes []Route) error {
	snap, err := s.snapshot.Build(routes, s.httpsRedirect)
	if err != nil {
		return fmt.Errorf("failed to build snapshot: %w", err)
	}
	return s.cache.SetSnapshot(context.Background(), nodeID, snap)
}

func (s *Server) NodeID() string {
	return nodeID
}
