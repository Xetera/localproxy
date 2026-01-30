package envoy

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"
)

type Manager struct {
	dataDir      string
	xdsAddress   string
	nodeID       string
	logLevel     string
	cmd          *exec.Cmd
	ctx          context.Context
	cancel       context.CancelFunc
	mu           sync.Mutex
	restartDelay time.Duration
	configPath   string
	shuttingDown bool
}

func NewManager(dataDir, xdsAddress, nodeID, logLevel string) *Manager {
	ctx, cancel := context.WithCancel(context.Background())
	if logLevel == "" {
		logLevel = "info"
	}
	return &Manager{
		dataDir:      dataDir,
		xdsAddress:   xdsAddress,
		nodeID:       nodeID,
		logLevel:     logLevel,
		ctx:          ctx,
		cancel:       cancel,
		restartDelay: 2 * time.Second,
		configPath:   filepath.Join(dataDir, "envoy-bootstrap.json"),
	}
}

func (m *Manager) Start() error {
	if err := m.writeBootstrapConfig(); err != nil {
		return fmt.Errorf("failed to write bootstrap config: %w", err)
	}

	go m.runLoop()
	return nil
}

func (m *Manager) Stop() {
	m.mu.Lock()
	m.shuttingDown = true
	m.mu.Unlock()

	m.cancel()
}

func (m *Manager) runLoop() {
	for {
		select {
		case <-m.ctx.Done():
			return
		default:
		}

		if err := m.spawn(); err != nil {
			log.Printf("envoy: failed to start: %v", err)
		}

		m.mu.Lock()
		shuttingDown := m.shuttingDown
		m.mu.Unlock()

		if shuttingDown {
			return
		}

		log.Printf("envoy: process exited, restarting in %v", m.restartDelay)
		select {
		case <-m.ctx.Done():
			return
		case <-time.After(m.restartDelay):
		}
	}
}

func (m *Manager) spawn() error {
	m.mu.Lock()
	if m.shuttingDown {
		m.mu.Unlock()
		return nil
	}
	cmd := exec.Command("envoy", "-c", m.configPath, "-l", m.logLevel, "--component-log-level", "main:warn")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	m.cmd = cmd
	m.mu.Unlock()

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start envoy: %w", err)
	}

	log.Printf("envoy: started with pid %d", cmd.Process.Pid)

	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	select {
	case err := <-done:
		return err
	case <-m.ctx.Done():
		m.mu.Lock()
		proc := m.cmd.Process
		m.mu.Unlock()

		if proc != nil {
			proc.Signal(os.Interrupt)
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				proc.Kill()
				<-done
			}
		}
		return nil
	}
}

func (m *Manager) writeBootstrapConfig() error {
	config := map[string]interface{}{
		"node": map[string]interface{}{
			"id":      m.nodeID,
			"cluster": "localproxy",
		},
		"dynamic_resources": map[string]interface{}{
			"ads_config": map[string]interface{}{
				"api_type":              "GRPC",
				"transport_api_version": "V3",
				"grpc_services": []map[string]interface{}{{
					"envoy_grpc": map[string]interface{}{
						"cluster_name": "xds_cluster",
					},
				}},
			},
			"lds_config": map[string]interface{}{
				"resource_api_version": "V3",
				"ads":                  map[string]interface{}{},
			},
			"cds_config": map[string]interface{}{
				"resource_api_version": "V3",
				"ads":                  map[string]interface{}{},
			},
		},
		"static_resources": map[string]interface{}{
			"clusters": []map[string]interface{}{{
				"name":            "xds_cluster",
				"connect_timeout": "5s",
				"type":            "STATIC",
				"lb_policy":       "ROUND_ROBIN",
				"typed_extension_protocol_options": map[string]interface{}{
					"envoy.extensions.upstreams.http.v3.HttpProtocolOptions": map[string]interface{}{
						"@type": "type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions",
						"explicit_http_config": map[string]interface{}{
							"http2_protocol_options": map[string]interface{}{},
						},
					},
				},
				"load_assignment": map[string]interface{}{
					"cluster_name": "xds_cluster",
					"endpoints": []map[string]interface{}{{
						"lb_endpoints": []map[string]interface{}{{
							"endpoint": map[string]interface{}{
								"address": map[string]interface{}{
									"socket_address": map[string]interface{}{
										"address":    "127.0.0.1",
										"port_value": 18000,
									},
								},
							},
						}},
					}},
				},
			}},
		},
		"admin": map[string]interface{}{
			"address": map[string]interface{}{
				"socket_address": map[string]interface{}{
					"address":    "127.0.0.1",
					"port_value": 9901,
				},
			},
		},
	}

	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(m.configPath, data, 0644)
}
