package proxy

import "net/netip"

type Route struct {
	Subdomain       string
	Endpoint        netip.AddrPort
	TCPPort         int
	ServiceProtocol string
	HasWildcard     bool
	FolderGroup     string
	CertPath        string
	KeyPath         string
}
