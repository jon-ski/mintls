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

// LeafParams describes the subject, usage, and lifetime for an end-entity (aka
// “leaf”) X.509 certificate issued by a CA in this package. Fill this out when
// you want a cert for a concrete thing (a server, a client, a device, an
// agent, etc.), NOT for a CA.
//
// # Field guide
//
// # CommonName
//
// Optional display label (e.g., device name or human-friendly identifier).
// Modern TLS does NOT use CommonName for hostname/IP validation. Put all
// connectable names in SANs (DNS/IPs). If you set CommonName, also include
// the same value in SANs when it should be considered valid for TLS.
//
// # DNS
//
// Subject Alternative Names for DNS hostnames the cert should be valid for.
//
// Examples: "api.example.com", "gateway.local", "*.svc.cluster.local".
//
// Notes:
//   - Wildcards are allowed for a single label (e.g., "*.example.com").
//   - Every hostname you expect clients to verify must appear here.
//   - If you only connect by IP, leave DNS empty.
//
// # IPs
//
// Subject Alternative Names for IP addresses (v4 or v6) the cert should be
// valid for. Use when clients connect by literal IP (common on internal
// networks, IoT, or Kubernetes NodeIPs).
//
// # ServerEKU
//
// Add Extended Key Usage: ServerAuth. Required for certificates presented by
// servers in TLS handshakes. Set this true for HTTPS servers, gRPC servers,
// MQTT brokers, OPC UA servers, etc.
//
// # ClientEKU
//
// Add Extended Key Usage: ClientAuth. Required for certificates presented by
// clients in mutual-TLS (mTLS). Set this true for API callers, device agents,
// headless scripts, service-to-service clients, etc.
//
// Best practice: issue different leaf certs for servers and clients (least
// privilege). Only set both ServerEKU and ClientEKU when a single identity
// must play both roles.
//
// # ValidFor
//
// Requested lifetime of the leaf certificate. Defaults to 397 days if zero.
// Rationale: stays under the common 398-day limit while allowing 1-year
// rotation windows. The actual notAfter will also be capped by the issuer
// CA’s remaining validity. Choose shorter values when you can automate
// rotation (e.g., 30–90 days).
//
// ─────────────────────────────────────────────────────────────────────────────
//
// # Minimal rules of thumb
//
//  1. Do not rely on CommonName for TLS verification; always populate SANs.
//  2. For hostname connections ⇒ put names in DNS.
//  3. For literal-IP connections ⇒ put addresses in IPs.
//  4. Servers need ServerEKU; mTLS clients need ClientEKU.
//  5. Prefer separate certs per role (server vs client) and per service.
//  6. Keep ValidFor short if you have automated renewal; otherwise keep it
//     ≤397d and implement a rotation process.
//
// ─────────────────────────────────────────────────────────────────────────────
//
// # Examples
//
// Example 1: HTTPS server for api.example.com and its internal alias.
//
//	lp := LeafParams{
//	  CommonName: "api.example.com",        // cosmetic
//	  DNS:        []string{"api.example.com", "api.int.example.net"},
//	  ServerEKU:  true,
//	  ValidFor:   90 * 24 * time.Hour,      // 90d, rotate quarterly
//	}
//	// certPEM, keyPEM, err := pki.IssueLeaf(ca, lp)
//
// Example 2: Internal service reached by IP (no DNS).
//
//	lp := LeafParams{
//	  CommonName: "inventory-node-03",      // label only
//	  IPs:        []net.IP{net.ParseIP("10.10.5.23")},
//	  ServerEKU:  true,
//	  ValidFor:   180 * 24 * time.Hour,
//	}
//
// Example 3: mTLS client identity for a device/agent.
//
//	lp := LeafParams{
//	  CommonName: "sensor-A12",             // shows up in logs/UX
//	  DNS:        []string{"sensor-a12.local"}, // optional if clients auth by CA+EKU only
//	  ClientEKU:  true,
//	  ValidFor:   60 * 24 * time.Hour,
//	}
//
// Example 4: Dual-role (server+client) for a simple peer service.
//
//	// Use sparingly; prefer separate certs when possible.
//	lp := LeafParams{
//	  CommonName: "peer-svc-east-1",
//	  DNS:        []string{"peer-svc-east-1.cluster.local"},
//	  ServerEKU:  true,
//	  ClientEKU:  true,
//	  ValidFor:   30 * 24 * time.Hour,
//	}
//
// Example 5: Wildcard for a namespace of ephemeral hosts.
//
//	lp := LeafParams{
//	  DNS:       []string{"*.build.example.com"},
//	  ServerEKU: true,
//	  ValidFor:  45 * 24 * time.Hour,
//	}
//
// ─────────────────────────────────────────────────────────────────────────────
//
// # Common pitfalls
//
//   - Missing SANs: modern clients ignore CommonName for verification—ensure DNS
//     or IPs contain every connectable name.
//   - Wrong EKU: servers with only ClientAuth (or clients with only ServerAuth)
//     will be rejected. Set the right EKU(s).
//   - Over-broad EKU: avoid setting both EKUs unless necessary.
//   - Overlong validity: long-lived certs increase risk. Prefer automation and
//     short lifetimes.
//   - Wildcard misuse: wildcards match a single leftmost label only; they do not
//     cover multiple levels (e.g., "*.a.example.com" does NOT cover "x.y.a…").
//   - CA cap: a leaf’s expiration cannot exceed the issuer CA’s expiration.
//
// ─────────────────────────────────────────────────────────────────────────────
//
// # Security/operations tips
//
//   - Use role-specific intermediate CAs if you need to constrain EKUs at the CA
//     level (server-only CA, client-only CA).
//   - Add unique, auditable identifiers in CommonName or as custom extensions if
//     you need to correlate certs to assets—do not leak secrets in certs.
//   - Rotate before expiry (e.g., renew at 2/3 of ValidFor). Budget for clock
//     skew and deployment time.
//   - Keep private keys non-exportable where possible (TPM/HSM), and prefer
//     on-device key generation with CSR flows in higher-security deployments.
//   - Avoid reusing a single leaf across many machines. Issue one per instance.
//
// ─────────────────────────────────────────────────────────────────────────────
//
// # Zero values & defaults
//
//   - If ValidFor == 0, the issuer will default to 397 days.
//   - CommonName may be empty.
//   - At least one SAN (DNS or IPs) is strongly recommended for TLS.
//   - If neither ServerEKU nor ClientEKU is set, issuance may succeed but many
//     clients will reject the cert—set the EKU(s) explicitly.
//
// In summary: put connectable names in SANs, set EKUs for the intended role,
// keep lifetimes reasonable, and prefer separate certs per role/service.
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

// IssueLeaf creates a new end-entity (leaf) certificate signed by the provided CA.
//
// A fresh keypair is generated, and the certificate subject, SANs, EKUs, and
// validity are taken from `params`. Use this for issuing server or client
// certificates in an mTLS setup.
//
// Inputs:
//
//   - caCert  – the certificate of the signing CA
//   - caKey   – private key corresponding to caCert
//   - params  – LeafParams describing the new cert (names, EKUs, validity)
//
// Returns:
//
//   - leafCert – parsed *x509.Certificate of the issued leaf
//   - leafKey  – the generated private key
//   - pair     – PEM-encoded certificate + key for convenience
//   - err      – error if issuance fails
//
// Example:
//
//	caCert, caKey := mustLoadCA()
//	lp := LeafParams{
//	  DNS:       []string{"api.example.com"},
//	  ServerEKU: true,
//	  ValidFor:  90 * 24 * time.Hour,
//	}
//	cert, key, pair, err := IssueLeaf(caCert, caKey, lp)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	// pair.CertPEM and pair.KeyPEM can now be written to disk or loaded into TLS.
//
// Notes:
//
//   - Always set at least one EKU (ServerEKU or ClientEKU).
//   - SANs (DNS/IPs) must match how clients connect.
//   - Validity is limited by the CA certificate’s own expiration.
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
