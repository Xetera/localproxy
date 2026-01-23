package envoy

import (
	"fmt"
	"os"
	"path/filepath"
)

const bootstrapTemplate = `
node:
  id: localproxy-envoy
  cluster: localproxy

dynamic_resources:
  ads_config:
    api_type: GRPC
    transport_api_version: V3
    grpc_services:
      - envoy_grpc:
          cluster_name: xds_cluster
  lds_config:
    resource_api_version: V3
    ads: {}
  cds_config:
    resource_api_version: V3
    ads: {}

static_resources:
  clusters:
    - name: xds_cluster
      connect_timeout: 1s
      type: STATIC
      lb_policy: ROUND_ROBIN
      typed_extension_protocol_options:
        envoy.extensions.upstreams.http.v3.HttpProtocolOptions:
          "@type": type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions
          explicit_http_config:
            http2_protocol_options: {}
      load_assignment:
        cluster_name: xds_cluster
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address:
                      address: %s
                      port_value: %d

admin:
  address:
    socket_address:
      address: 127.0.0.1
      port_value: 9901
`

func GenerateBootstrap(xdsHost string, xdsPort int, outputDir string) (string, error) {
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create output dir: %w", err)
	}

	content := fmt.Sprintf(bootstrapTemplate, xdsHost, xdsPort)
	path := filepath.Join(outputDir, "envoy.yaml")

	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		return "", fmt.Errorf("failed to write bootstrap: %w", err)
	}

	return path, nil
}
