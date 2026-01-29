package discovery

import (
	"context"
	"fmt"
	"log"
	"net/netip"
	"strings"
	"time"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	scan "github.com/praetorian-inc/fingerprintx/pkg/scan"
)

type ScanTarget struct {
	IP   string
	Port int
}

type ServiceInfo struct {
	IP       string
	Port     int
	Protocol string
	Name     string
	Product  string
	Version  string
}

func DiscoverServices(ctx context.Context, targets []ScanTarget, results chan<- []ServiceInfo) {
	go func() {
		defer close(results)

		t := make([]plugins.Target, 0)
		for _, a := range targets {
			ip, err := netip.ParseAddr(strings.TrimSpace(a.IP))
			if err != nil {
				fmt.Println(err)
				continue
			}
			port := uint16(a.Port)
			address := netip.AddrPortFrom(ip, port)
			t = append(t, plugins.Target{
				Address: address,
				Host:    "",
			})
		}

		if len(t) == 0 {
			return
		}

		retryDelays := []time.Duration{0, 3 * time.Second, 3 * time.Second}

		for attempt, delay := range retryDelays {
			if delay > 0 {
				select {
				case <-ctx.Done():
					return
				case <-time.After(delay):
				}
			}

			log.Printf("fingerprint: scanning %d targets (attempt %d)\n", len(t), attempt+1)
			scanned, err := scan.ScanTargets(t, scan.Config{
				UDP:            false,
				FastMode:       false,
				Verbose:        false,
				DefaultTimeout: time.Second,
			})
			if err != nil {
				log.Printf("fingerprint: scan error (attempt %d): %v\n", attempt+1, err)
				continue
			}

			log.Printf("fingerprint: scan returned %d results\n", len(scanned))
			if len(scanned) > 0 {
				var services []ServiceInfo
				for _, s := range scanned {
					log.Printf("	%s:%d (%s)\n", s.IP, s.Port, s.Protocol)
					services = append(services, ServiceInfo{
						IP:       s.IP,
						Port:     s.Port,
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
		}
	}()
}
