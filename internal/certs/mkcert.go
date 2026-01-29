package certs

import (
	"crypto/tls"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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

func newMkcertCommand(certsDir string, certPath string, keyPath string) *exec.Cmd {
	cmd := exec.Command("mkcert",
		"-cert-file", certPath,
		"-key-file", keyPath,
		"proxy.localhost",
		"*.proxy.localhost",
		"proxy.internal",
		"*.proxy.internal",
	)
	cmd.Dir = certsDir
	return cmd
}

func (m *CertManager) generateWildcardCert() error {
	fmt.Println("Generating wildcard certificate...", m.wildcardCertPath)
	if _, err := os.Stat(m.wildcardCertPath); err == nil {
		if _, err := os.Stat(m.wildcardKeyPath); err == nil {
			return nil
		}
	}

	cmd := newMkcertCommand(m.certsDir, m.wildcardCertPath, m.wildcardKeyPath)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to generate wildcard cert: %w", err)
	}
	return nil
}

func (m *CertManager) GetWildcardCert() (certPath, keyPath string) {
	return m.wildcardCertPath, m.wildcardKeyPath
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
