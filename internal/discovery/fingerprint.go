package discovery

import (
	"context"
	"fmt"
	"net/netip"
	"strings"

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

func DiscoverServices(ctx context.Context, targets []ScanTarget) ([]ServiceInfo, error) {
	t := make([]plugins.Target, 0)
	for _, a := range targets {
		ip, err := netip.ParseAddr(strings.TrimSpace(a.IP))
		if err != nil {
			fmt.Println(err)
			continue
		}
		fmt.Println(ip)
		port := uint16(a.Port)
		address := netip.AddrPortFrom(ip, port)
		fmt.Println(address, ip, port)
		t = append(t, plugins.Target{
			Address: address,
			Host:    "",
		})
	}

	fmt.Println("targets", t)
	scanned, error := scan.ScanTargets(t, scan.Config{
		UDP:      false,
		FastMode: false,
		Verbose:  true,
	})
	if error != nil {
		fmt.Println("!scan error", error)
		return nil, error
	}
	fmt.Println("done: ", scanned)
	for _, s := range scanned {
		fmt.Println(string(s.Raw))
		fmt.Println(s.Protocol)
	}

	return nil, nil
}
