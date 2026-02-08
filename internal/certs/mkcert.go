package certs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/smallstep/truststore"
)

type CertManager struct {
	certsDir string
	certs    map[string]*CertPaths
	mu       sync.RWMutex
	caKey    *ecdsa.PrivateKey
	caCert   *x509.Certificate
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
	if err := m.loadOrCreateCA(); err != nil {
		return err
	}
	return m.EnsureCert("localhost")
}

func (m *CertManager) loadOrCreateCA() error {
	caKeyPath := filepath.Join(m.certsDir, "rootCA-key.pem")
	caCertPath := filepath.Join(m.certsDir, "rootCA.pem")

	keyData, keyErr := os.ReadFile(caKeyPath)
	certData, certErr := os.ReadFile(caCertPath)

	if keyErr == nil && certErr == nil {
		keyBlock, _ := pem.Decode(keyData)
		if keyBlock != nil {
			key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
			if err != nil {
				return fmt.Errorf("failed to parse CA key: %w", err)
			}
			m.caKey = key
		}

		certBlock, _ := pem.Decode(certData)
		if certBlock != nil {
			cert, err := x509.ParseCertificate(certBlock.Bytes)
			if err != nil {
				return fmt.Errorf("failed to parse CA cert: %w", err)
			}
			m.caCert = cert
		}

		if m.caKey != nil && m.caCert != nil {
			return m.installCA(caCertPath)
		}
	}

	log.Println("certs: generating new root CA")
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate CA key: %w", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"localproxy development CA"},
			CommonName:   "localproxy Root CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("failed to create CA cert: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("failed to parse created CA cert: %w", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("failed to marshal CA key: %w", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	if err := os.WriteFile(caKeyPath, keyPEM, 0600); err != nil {
		return fmt.Errorf("failed to write CA key: %w", err)
	}
	if err := os.WriteFile(caCertPath, certPEM, 0644); err != nil {
		return fmt.Errorf("failed to write CA cert: %w", err)
	}

	m.caKey = key
	m.caCert = cert

	return m.installCA(caCertPath)
}

func (m *CertManager) installCA(caCertPath string) error {
	if m.isCATrusted() {
		log.Println("certs: root CA already trusted")
		return nil
	}
	log.Println("certs: installing root CA in system trust store")
	return truststore.InstallFile(caCertPath,
		truststore.WithFirefox(),
		truststore.WithJava(),
	)
}

func (m *CertManager) isCATrusted() bool {
	fingerprint := sha1.Sum(m.caCert.Raw)
	fingerprintHex := strings.ToUpper(hex.EncodeToString(fingerprint[:]))

	cmd := exec.Command("security", "find-certificate", "-a", "-Z", "/Library/Keychains/System.keychain")
	out, err := cmd.Output()
	if err != nil {
		return false
	}

	lines := strings.Split(string(out), "\n")
	for i, line := range lines {
		if strings.Contains(line, "SHA-1 hash:") {
			hash := strings.TrimSpace(strings.TrimPrefix(line, "SHA-1 hash:"))
			if hash == fingerprintHex {
				for j := i + 1; j < len(lines) && j < i+20; j++ {
					if strings.Contains(lines[j], `"labl"<blob>="localproxy Root CA"`) {
						return m.isCATrustSettingsValid()
					}
				}
			}
		}
	}
	return false
}

func (m *CertManager) isCATrustSettingsValid() bool {
	cmd := exec.Command("security", "dump-trust-settings", "-d")
	out, err := cmd.Output()
	if err != nil {
		return false
	}

	lines := strings.Split(string(out), "\n")
	for i, line := range lines {
		if strings.Contains(line, "localproxy Root CA") {
			for j := i + 1; j < len(lines) && j < i+10; j++ {
				if strings.Contains(lines[j], "kSecTrustSettingsResultTrustRoot") {
					return true
				}
				if strings.HasPrefix(strings.TrimSpace(lines[j]), "Cert ") {
					break
				}
			}
		}
	}
	return false
}

func (m *CertManager) EnsureCert(subdomain string) error {
	return m.ensureCertInternal(subdomain, false)
}

func (m *CertManager) EnsureWildcardCert(subdomain string) error {
	return m.ensureCertInternal(subdomain, true)
}

func (m *CertManager) ensureCertInternal(subdomain string, wildcard bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	cacheKey := subdomain
	if wildcard {
		cacheKey = "wildcard_" + subdomain
	}

	if _, exists := m.certs[cacheKey]; exists {
		return nil
	}

	certPath := filepath.Join(m.certsDir, cacheKey+".pem")
	keyPath := filepath.Join(m.certsDir, cacheKey+"-key.pem")

	if _, err := os.Stat(certPath); err == nil {
		if _, err := os.Stat(keyPath); err == nil {
			m.certs[cacheKey] = &CertPaths{CertPath: certPath, KeyPath: keyPath}
			return nil
		}
	}

	var dnsNames []string
	if subdomain == "localhost" {
		dnsNames = []string{"localhost", "proxy.localhost", "proxy.internal"}
	} else if wildcard {
		dnsNames = []string{
			"*." + subdomain + ".localhost",
			"*." + subdomain + ".internal",
			subdomain + ".localhost",
			subdomain + ".internal",
		}
	} else {
		dnsNames = []string{subdomain + ".localhost", subdomain + ".internal"}
	}

	log.Printf("certs: generating certificate for %v", dnsNames)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate key: %w", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"localproxy"},
			CommonName:   dnsNames[0],
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(2, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              dnsNames,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, m.caCert, &key.PublicKey, m.caKey)
	if err != nil {
		return fmt.Errorf("failed to create cert: %w", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("failed to marshal key: %w", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return fmt.Errorf("failed to write key: %w", err)
	}
	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		return fmt.Errorf("failed to write cert: %w", err)
	}

	m.certs[cacheKey] = &CertPaths{CertPath: certPath, KeyPath: keyPath}
	return nil
}

func (m *CertManager) GetWildcardCert(subdomain string) (certPath, keyPath string, ok bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	cacheKey := "wildcard_" + subdomain
	paths, exists := m.certs[cacheKey]
	if !exists {
		return "", "", false
	}
	return paths.CertPath, paths.KeyPath, true
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
