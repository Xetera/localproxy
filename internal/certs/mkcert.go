package certs

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
)

type CertManager struct {
	certsDir string
	certs    map[string]*CertPaths
	mu       sync.RWMutex
}

type CertPaths struct {
	CertPath string
	KeyPath  string
}

func NewCertManager(dataDir string) *CertManager {
	certsDir := filepath.Join(dataDir, "certs")
	return &CertManager{
		certsDir: certsDir,
		certs:    make(map[string]*CertPaths),
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
	return m.EnsureCert("localhost")
}

func (m *CertManager) EnsureCert(subdomain string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.certs[subdomain]; exists {
		return nil
	}

	certPath := filepath.Join(m.certsDir, subdomain+".pem")
	keyPath := filepath.Join(m.certsDir, subdomain+"-key.pem")

	if _, err := os.Stat(certPath); err == nil {
		if _, err := os.Stat(keyPath); err == nil {
			m.certs[subdomain] = &CertPaths{CertPath: certPath, KeyPath: keyPath}
			return nil
		}
	}

	var domains []string
	if subdomain == "localhost" {
		domains = []string{"localhost", "proxy.localhost", "proxy.internal"}
	} else {
		domains = []string{subdomain + ".localhost", subdomain + ".internal"}
	}

	log.Printf("certs: generating certificate for %v", domains)
	args := append([]string{"-cert-file", certPath, "-key-file", keyPath}, domains...)
	cmd := exec.Command("mkcert", args...)
	cmd.Dir = m.certsDir
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to generate cert for %v: %w", domains, err)
	}

	m.certs[subdomain] = &CertPaths{CertPath: certPath, KeyPath: keyPath}
	return nil
}

func (m *CertManager) GetCert(subdomain string) (certPath, keyPath string, ok bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	paths, exists := m.certs[subdomain]
	if !exists {
		return "", "", false
	}
	return paths.CertPath, paths.KeyPath, true
}

func (m *CertManager) GetAllCerts() map[string]*CertPaths {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make(map[string]*CertPaths)
	for k, v := range m.certs {
		result[k] = v
	}
	return result
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
