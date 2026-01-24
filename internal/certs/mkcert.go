package certs

import (
	"crypto/tls"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

type CertManager struct {
	certsDir         string
	cache            map[string]*tls.Certificate
	mu               sync.RWMutex
	wildcardCertPath string
	wildcardKeyPath  string
}

func NewCertManager(dataDir string) *CertManager {
	certsDir := filepath.Join(dataDir, "certs")
	return &CertManager{
		certsDir:         certsDir,
		cache:            make(map[string]*tls.Certificate),
		wildcardCertPath: filepath.Join(certsDir, "wildcard.pem"),
		wildcardKeyPath:  filepath.Join(certsDir, "wildcard-key.pem"),
	}
}

func (m *CertManager) Init() error {
	if err := os.MkdirAll(m.certsDir, 0755); err != nil {
		return fmt.Errorf("failed to create certs dir: %w", err)
	}
	if err := m.checkMkcert(); err != nil {
		return err
	}
	if err := m.installCA(); err != nil {
		return err
	}
	return m.generateWildcardCert()
}

func (m *CertManager) generateWildcardCert() error {
	fmt.Println("Generating wildcard certificate...", m.wildcardCertPath)
	if _, err := os.Stat(m.wildcardCertPath); err == nil {
		if _, err := os.Stat(m.wildcardKeyPath); err == nil {
			return nil
		}
	}

	cmd := exec.Command("mkcert",
		"-cert-file", m.wildcardCertPath,
		"-key-file", m.wildcardKeyPath,
		"proxy.localhost",
		"*.proxy.localhost",
	)
	cmd.Dir = m.certsDir
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to generate wildcard cert: %w", err)
	}
	return nil
}

func (m *CertManager) GetWildcardCert() (certPath, keyPath string) {
	return m.wildcardCertPath, m.wildcardKeyPath
}

func (m *CertManager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	domain := m.getDomainForCert(hello.ServerName)

	m.mu.RLock()
	cert, ok := m.cache[domain]
	m.mu.RUnlock()
	if ok {
		return cert, nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if cert, ok := m.cache[domain]; ok {
		return cert, nil
	}

	cert, err := m.generateCert(domain)
	if err != nil {
		return nil, err
	}

	m.cache[domain] = cert
	return cert, nil
}

func (m *CertManager) getDomainForCert(serverName string) string {
	serverName = strings.TrimSuffix(serverName, ".proxy.localhost")
	parts := strings.Split(serverName, ".")
	if len(parts) <= 2 {
		return "proxy.localhost"
	}
	return parts[len(parts)-2] + ".proxy.localhost"
}

func (m *CertManager) generateCert(domain string) (*tls.Certificate, error) {
	certPath := filepath.Join(m.certsDir, domain+".pem")
	keyPath := filepath.Join(m.certsDir, domain+"-key.pem")

	if _, err := os.Stat(certPath); err == nil {
		if _, err := os.Stat(keyPath); err == nil {
			cert, err := tls.LoadX509KeyPair(certPath, keyPath)
			if err == nil {
				return &cert, nil
			}
		}
	}

	wildcard := "*." + domain
	cmd := exec.Command("mkcert",
		"-cert-file", certPath,
		"-key-file", keyPath,
		domain,
		wildcard,
	)
	cmd.Dir = m.certsDir
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("failed to generate cert for %s: %w", domain, err)
	}

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}

	return &cert, nil
}

func (m *CertManager) checkMkcert() error {
	_, err := exec.LookPath("mkcert")
	if err != nil {
		return fmt.Errorf("mkcert not found in PATH; please install it: https://github.com/FiloSottile/mkcert")
	}
	return nil
}

func (m *CertManager) installCA() error {
	cmd := exec.Command("mkcert", "-install")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
