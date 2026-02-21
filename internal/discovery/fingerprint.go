package discovery

import (
	"context"
	"log"
	"net/netip"
	"time"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	scan "github.com/praetorian-inc/fingerprintx/pkg/scan"
)

type ServiceInfo struct {
	Endpoint netip.AddrPort
	Protocol string
	Version  string
}

func ProbeEndpoints(ctx context.Context, addrs []netip.AddrPort, results chan<- []ServiceInfo) {
	go func() {
		defer close(results)

		t := make([]plugins.Target, 0)
		for _, address := range addrs {
			t = append(t, plugins.Target{
				Address: address,
				Host:    "localhost",
			})
		}

		if len(t) == 0 {
			return
		}

		retryDelays := []time.Duration{0, 3 * time.Second, 6 * time.Second}

		for attempt, delay := range retryDelays {
			if delay > 0 {
				select {
				case <-ctx.Done():
					return
				case <-time.After(delay):
				}
			}

			log.Printf("fingerprint: scanning %d targets (attempt %d)\n", len(t), attempt+1)
			for _, target := range t {
				log.Printf("	Scanning target %s\n", target.Address.String())
			}
			scanned, err := scan.ScanTargets(t, scan.Config{
				UDP:            false,
				FastMode:       false,
				Verbose:        false,
				DefaultTimeout: time.Second * time.Duration(attempt),
			})
			if err != nil {
				log.Printf("fingerprint: scan error (attempt %d): %v\n", attempt+1, err)
				continue
			}

			log.Printf("fingerprint: scan returned %d results\n", len(scanned))
			var services []ServiceInfo
			if len(scanned) == 0 {
				// results <- services
				continue
			}

			for _, s := range scanned {
				log.Printf("	%s:%d (%s)\n", s.IP, s.Port, s.Protocol)
				addr, err := netip.ParseAddr(s.IP)
				if err != nil {
					log.Printf("fingerprint: failed to parse IP %s: %v\n", s.IP, err)
					continue
				}
				endpoint := netip.AddrPortFrom(addr, uint16(s.Port))
				services = append(services, ServiceInfo{
					Endpoint: endpoint,
					Protocol: s.Protocol,
					Version:  s.Version,
				})
			}
			select {
			case results <- services:
			case <-ctx.Done():
			}
			return
		}
	}()
}
