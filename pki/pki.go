// Package pki provides opinionated, Ed25519-only PKI utilities for Go services.
//
// It is designed to simplify creating and managing a minimal certificate
// hierarchy for mutual TLS (mTLS) with strict, modern defaults:
//
//   - Ed25519 keys only (RSA/ECDSA unsupported)
//   - TLS 1.3 assumed
//   - Root CA validity: 5 years
//   - Leaf validity: 397 days
//   - SANs required (DNS/IP); CN-only certs rejected
//   - KeyUsage/EKU restricted to least privilege
//   - Keys written as PKCS#8 DER (0600)
//   - Certs written as PEM (0644)
//   - All file writes are atomic (temp + rename)
//
// The package is intentionally narrow in scope:
// it does not handle key distribution, secure storage, or higher-layer
// authentication/authorization. It only generates, parses, and persists
// X.509 certificates and keys for mTLS use cases.
//
// Typical usage includes:
//   - Bootstrapping a private root CA
//   - Issuing short-lived server/client certs
//   - Writing certs/keys to disk with correct permissions
//   - Parsing PEM/DER material back into Go crypto types
//
// Example:
//
//	package main
//
//	import (
//		"net"
//		"github.com/jon-ski/mintls/pki"
//	)
//
//	func main() {
//		// Root CA
//		caCert, caKey, caPair, _ := pki.CreateCA(pki.CAParams{
//			CommonName: "Root CA",
//		})
//
//		// Write CA to disk
//		_ = pki.WriteCertPEM("ca.crt", caPair.CertDER, 0o644)
//		_ = pki.WritePKCS8KeyPEM("ca.key", caPair.KeyPKCS8, 0o600)
//
//		// Server leaf
//		_, _, srvPair, _ := pki.IssueLeaf(caCert, caKey, pki.LeafParams{
//			DNS:       []string{"localhost"},
//			IPs:       []net.IP{net.ParseIP("127.0.0.1")},
//			ServerEKU: true,
//		})
//
//		_ = pki.WriteCertPEM("server.crt", srvPair.CertDER, 0o644)
//		_ = pki.WritePKCS8KeyPEM("server.key", srvPair.KeyPKCS8, 0o600)
//	}
//
// This example demonstrates generating a root CA, issuing a server certificate,
// and persisting them as PEM files with correct modes for later use in TLS.
package pki

import (
	"crypto"
	"crypto/x509"
	"errors"
	"io/fs"
	"net"
	"time"
)

const (
	DefaultCAValidFor   = 5 * 365 * 24 * time.Hour // 5 years
	DefaultLeafValidFor = 397 * 24 * time.Hour     // ~13 months
)

// CAParams defines root CA creation parameters.
type CAParams struct {
	CommonName string        // CN=Root CA
	ValidFor   time.Duration // default: 5y
}

// LeafParams defines Leaf certificate issuance.
type LeafParams struct {
	CommonName string        // optional, typically device name
	DNS        []string      // SANs
	IPs        []net.IP      // SANs
	ServerEKU  bool          // add ServerAuth EKU
	ClientEKU  bool          // add ClientAuth EKU
	ValidFor   time.Duration // default: 397d
}

// Pair holds key material + encoded forms.
type Pair struct {
	CertDER  []byte // raw DER
	KeyPKCS8 []byte // PKCS#8 DER
	CertPEM  []byte // PEM-encoded cert
	KeyPEM   []byte // PEM-encoded key
}

// CreateCA generates a new Ed25519 root CA.
func CreateCA(params CAParams) (caCert *x509.Certificate, caKey crypto.Signer, pair Pair, err error) {
	return nil, nil, Pair{}, errors.New("not implemented")
}

// IssueLeaf issues a server or client cert signed by the given CA.
func IssueLeaf(caCert *x509.Certificate, caKey crypto.Signer, params LeafParams) (leafCert *x509.Certificate, leafKey crypto.Signer, pair Pair, err error) {
	return nil, nil, Pair{}, errors.New("not implemented")
}

// ============
// File Helpers
// ============

// WriteCertPEM writes a cert to path (0600/0644 enforced).
func WriteCertPEM(path string, der []byte, mode fs.FileMode) error {
	return errors.New("not implemented")
}

// WritePKCS8KeyPEM writes a private key to path (0600 enforced).
func WritePKCS8KeyPEM(path string, pkcs8 []byte, mode fs.FileMode) error {
	return errors.New("not implemented")
}

// AtomicWrite writes data safely to path (temp + rename).
func AtomicWrite(path string, data []byte, mode fs.FileMode) error {
	return errors.New("not implemented")
}

// =============
// Parse Helpers
// =============

// ParseCertPEM parses a PEM-encoded cert.
func ParseCertPEM(pemBytes []byte) (*x509.Certificate, error) {
	return nil, errors.New("not implemented")
}

// ParseAnyKeyPEM parses a PEM-encoded Ed25519 PKCS#8 key.
func ParseAnyKeyPEM(pemBytes []byte) (crypto.Signer, error) {
	return nil, errors.New("not implemented")
}
