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
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"runtime"
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

// CreateCA creates a self-signed Ed25519 Certificate Authority (CA) certificate
// with strict, CA-appropriate defaults and returns:
//   - caCert: the parsed *x509.Certificate for in-process use (e.g., issuing leaves)
//   - caKey:  the Ed25519 private key as a crypto.Signer
//   - pair:   DER-encoded cert and PKCS#8-encoded private key for persistence
//
// Parameters
//   - CAParams.CommonName (optional): CN for the CA's subject; empty is allowed.
//   - CAParams.ValidFor (optional): overall validity window. Default = 5 years
//     if ≤ 0. NotBefore is skewed 5 minutes into the past to avoid clock drift issues.
//
// Security / Policy
//   - Ed25519 only (SignatureAlgorithm = PureEd25519).
//   - IsCA = true, BasicConstraintsValid = true.
//   - KeyUsage = CertSign | CRLSign only (least-privilege for a CA).
//   - MaxPathLenZero = true (no subordinate CAs).
//   - Serial = 128-bit cryptographically random.
//
// Persistence
//   - pair.CertDER is an x509 certificate in DER.
//   - pair.KeyPKCS8 is the PKCS#8 DER private key. Persist with WritePKCS8KeyPEM (0600).
//
// Example
//
//	caCert, caKey, caPair, err := pki.CreateCA(pki.CAParams{CommonName: "Root CA"})
//	if err != nil { log.Fatal(err) }
//	_ = pki.WriteCertPEM("certs/ca.crt", caPair.CertDER, 0o644)
//	_ = pki.WritePKCS8KeyPEM("certs/ca.key", caPair.KeyPKCS8, 0o600)
func CreateCA(params CAParams) (caCert *x509.Certificate, caKey crypto.Signer, pair Pair, err error) {
	// Defaults.
	validFor := params.ValidFor
	if validFor <= 0 {
		validFor = DefaultCAValidFor
	}

	// Ed25519 keypair.
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, Pair{}, fmt.Errorf("ed25519.GenerateKey: %w", err)
	}

	// 128-bit cryptographically random serial.
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, nil, Pair{}, fmt.Errorf("rand.Int(serial): %w", err)
	}

	now := time.Now().UTC()
	notBefore := now.Add(-5 * time.Minute) // small backdate to tolerate clock skew
	notAfter := notBefore.Add(validFor)

	spki, err := x509.MarshalPKIXPublicKey(priv.Public())
	if err != nil {
		return nil, nil, Pair{}, fmt.Errorf("MarshalPKIXPublicKey: %w", err)
	}

	// Extract the subjectPublicKey BIT STRING from SPKI:
	var spkiSeq asn1.RawValue
	if _, err := asn1.Unmarshal(spki, &spkiSeq); err != nil {
		return nil, nil, Pair{}, fmt.Errorf("asn1.Unmarshal SPKI: %w", err)
	}
	// spkiSeq.Bytes contains the SEQUENCE; parse inner to get the BIT STRING:
	var alg pkix.AlgorithmIdentifier
	var spk asn1.BitString
	if _, err := asn1.Unmarshal(spkiSeq.Bytes, &[]any{&alg, &spk}); err != nil {
		return nil, nil, Pair{}, fmt.Errorf("asn1.Unmarshal SPKI seq: %w", err)
	}
	ski := sha1.Sum(spk.Bytes) // SHA-1 of subjectPublicKey

	tpl := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: params.CommonName,
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		// CA constraints
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true, // do not allow subordinate CAs

		// Least-privilege for CA.
		KeyUsage:           x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SignatureAlgorithm: x509.PureEd25519,

		// No EKUs for a CA.
		ExtKeyUsage: nil,

		// SKI
		SubjectKeyId: ski[:],
	}

	// Self-sign
	der, err := x509.CreateCertificate(rand.Reader, &tpl, &tpl, priv.Public(), priv)
	if err != nil {
		return nil, nil, Pair{}, fmt.Errorf("CreateCertificate: %w", err)
	}

	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, Pair{}, fmt.Errorf("ParseCertificate: %w", err)
	}

	pkcs8, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, Pair{}, fmt.Errorf("MarshalPKCS8PrivateKey: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})

	return parsed, priv, Pair{
		CertDER:  der,
		KeyPKCS8: pkcs8,
		CertPEM:  certPEM,
		KeyPEM:   keyPEM,
	}, nil
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
	if caCert == nil || caKey == nil {
		return nil, nil, Pair{}, fmt.Errorf("nil caCert or caKey")
	}
	if err := validateLeafParams(params); err != nil {
		return nil, nil, Pair{}, err
	}

	notBefore, notAfter := leafNotBeforeAfter(params.ValidFor)
	if caCert.NotAfter.Before(notAfter) {
		notAfter = caCert.NotAfter
	}

	serial, err := randSerial128()
	if err != nil {
		return nil, nil, Pair{}, err
	}
	priv, err := genLeafKey()
	if err != nil {
		return nil, nil, Pair{}, err
	}

	tpl := buildLeafTemplate(params, serial, notBefore, notAfter, caCert.SubjectKeyId)

	der, err := x509.CreateCertificate(rand.Reader, tpl, caCert, priv.Public(), caKey)
	if err != nil {
		return nil, nil, Pair{}, fmt.Errorf("CreateCertificate: %w", err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, Pair{}, fmt.Errorf("ParseCertificate: %w", err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, Pair{}, fmt.Errorf("MarshalPKCS8PrivateKey: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})

	return c, priv, Pair{
		CertDER:  der,
		KeyPKCS8: pkcs8,
		CertPEM:  certPEM,
		KeyPEM:   keyPEM,
	}, nil
}

func validateLeafParams(p LeafParams) error {
	if !p.ServerEKU && !p.ClientEKU {
		return fmt.Errorf("at least one EKU must be set (ServerEKU and/or ClientEKU)")
	}
	if p.ServerEKU && len(p.DNS) == 0 && len(p.IPs) == 0 {
		return fmt.Errorf("server EKU requires at least one SAN (DNS or IP)")
	}
	return nil
}

func leafNotBeforeAfter(validFor time.Duration) (time.Time, time.Time) {
	if validFor <= 0 {
		validFor = DefaultLeafValidFor
	}
	nb := time.Now().UTC().Add(-5 * time.Minute)
	return nb, nb.Add(validFor)
}

func randSerial128() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, limit)
}

func genLeafKey() (ed25519.PrivateKey, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	return priv, err
}

func buildLeafTemplate(p LeafParams, serial *big.Int, notBefore, notAfter time.Time, aki []byte) *x509.Certificate {
	ekus := make([]x509.ExtKeyUsage, 0, 2)
	if p.ServerEKU {
		ekus = append(ekus, x509.ExtKeyUsageServerAuth)
	}
	if p.ClientEKU {
		ekus = append(ekus, x509.ExtKeyUsageClientAuth)
	}

	// Defensive copy for IP slice
	var ips []net.IP
	if len(p.IPs) > 0 {
		ips = make([]net.IP, len(p.IPs))
		copy(ips, p.IPs)
	}

	return &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: p.CommonName},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  false,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           ekus,
		SignatureAlgorithm:    x509.PureEd25519,
		DNSNames:              p.DNS,
		IPAddresses:           ips,
		AuthorityKeyId:        aki,
	}
}

// ============
// File Helpers
// ============

// WriteCertPEM writes a single X.509 certificate (DER) to a PEM file using AtomicWrite.
//
// Behavior:
//   - Validates certDER parses as an x509 certificate.
//   - Encodes as a PEM block with type "CERTIFICATE".
//   - Persists atomically via AtomicWrite with the provided permissions.
//
// Permissions:
//   - Use 0o644 for certificates (public material).
//   - Private keys should be written separately with 0o600 via WritePKCS8KeyPEM.
//
// Example:
//
//	if err := pki.WriteCertPEM("certs/ca.crt", caPair.CertDER, 0o644); err != nil {
//	    log.Fatal(err)
//	}
func WriteCertPEM(path string, certDER []byte, perm fs.FileMode) error {
	// Validate DER to avoid persisting broken data.
	if _, err := x509.ParseCertificate(certDER); err != nil {
		return fmt.Errorf("invalid certificate DER: %w", err)
	}

	// Encode to PEM.
	var buf bytes.Buffer
	if err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		return fmt.Errorf("pem.Encode: %w", err)
	}

	// Atomic write to disk.
	if err := AtomicWrite(path, buf.Bytes(), perm); err != nil {
		return fmt.Errorf("atomic write: %w", err)
	}
	return nil
}

// WritePKCS8KeyPEM writes a PKCS#8 private key (DER) to a PEM file using AtomicWrite.
//
// Behavior:
//   - Validates the DER as PKCS#8 and enforces Ed25519-only (per project policy).
//   - Encodes as a PEM block with type "PRIVATE KEY" (unencrypted).
//   - Persists atomically via AtomicWrite with the provided permissions.
//
// Permissions:
//   - Use 0o600 for private keys (recommended).
//   - On Windows, os.Chmod/permissions are advisory; for strict ACLs use icacls.
//
// Security notes:
//   - This function does NOT encrypt the PEM at rest. Prefer OS disk encryption/HSM/YubiKey
//     if you require at-rest key protection.
//   - Keep key and certificate in separate files; never bundle private keys with public certs.
//
// Example:
//
//	if err := pki.WritePKCS8KeyPEM("certs/ca.key", caPair.KeyPKCS8, 0o600); err != nil {
//	    log.Fatal(err)
//	}
func WritePKCS8KeyPEM(path string, pkcs8DER []byte, perm fs.FileMode) error {
	// Validate PKCS#8 and enforce Ed25519-only policy.
	keyAny, err := x509.ParsePKCS8PrivateKey(pkcs8DER)
	if err != nil {
		return fmt.Errorf("invalid PKCS#8 private key DER: %w", err)
	}
	if _, ok := keyAny.(ed25519.PrivateKey); !ok {
		return fmt.Errorf("unsupported private key type: only Ed25519 is allowed")
	}

	// Encode to PEM (unencrypted).
	var buf bytes.Buffer
	if err := pem.Encode(&buf, &pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8DER}); err != nil {
		return fmt.Errorf("pem.Encode: %w", err)
	}

	// Atomic write to disk with requested permissions.
	if err := AtomicWrite(path, buf.Bytes(), perm); err != nil {
		return fmt.Errorf("atomic write: %w", err)
	}
	return nil
}

// AtomicWrite writes data to path atomically with the requested file mode.
//
// Semantics:
//   - Writes into a temporary file created in the same directory as path.
//   - Sets the temp file permission to `mode` immediately.
//   - fsyncs the temp file, then renames it over the target (atomic on POSIX).
//   - Best-effort directory fsync after rename to persist the entry.
//   - On Windows, if the destination exists and rename fails, it falls back to
//     removing the destination and renaming (not fully atomic on Windows).
//   - Ensures the final file has permission `mode` (post-rename chmod).
//
// Notes:
//   - Parent directories are created with 0755 if missing.
//   - `mode` is honored on POSIX; on Windows, permissions are advisory.
//   - Callers should use 0o600 for private keys and 0o644 for certificates.
//
// Example:
//
//	if err := AtomicWrite("certs/ca.crt", pemBytes, 0o644); err != nil { return err }
func AtomicWrite(path string, data []byte, mode fs.FileMode) error {
	dir := filepath.Dir(path)
	base := filepath.Base(path)

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}

	// Create a temp file in the same directory to keep rename atomic on POSIX.
	tmp, err := os.CreateTemp(dir, "."+base+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		// Best-effort cleanup if we return early.
		_ = os.Remove(tmpName)
	}()

	// Apply requested permissions on the temp file early.
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temp: %w", err)
	}

	// Write all data.
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp: %w", err)
	}

	// Flush to storage.
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("fsync temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp: %w", err)
	}

	// Rename over target. On POSIX this is atomic and replaces any existing file.
	if err := os.Rename(tmpName, path); err != nil {
		// Windows cannot replace an existing file with os.Rename.
		if runtime.GOOS == "windows" {
			_ = os.Remove(path) // best-effort; not atomic on Windows
			if err2 := os.Rename(tmpName, path); err2 != nil {
				return fmt.Errorf("rename temp -> %s (windows): %w", path, err2)
			}
		} else {
			return fmt.Errorf("rename temp -> %s: %w", path, err)
		}
	}

	// Ensure final permissions (in case of umask or platform quirks).
	if err := os.Chmod(path, mode); err != nil {
		return fmt.Errorf("chmod final: %w", err)
	}

	// Best-effort fsync of directory to persist the rename.
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync() // some platforms may not support directory fsync; ignore error
		_ = d.Close()
	}

	return nil
}

// =============
// Parse Helpers
// =============

// ParseCertPEM parses a single X.509 certificate from a PEM buffer.
//
// Behavior:
//   - Scans pemBytes for the first block with Type == "CERTIFICATE".
//   - Returns the parsed *x509.Certificate.
//   - If no certificate block is found or parsing fails, returns an error.
//
// Notes:
//   - If pemBytes contains multiple CERTIFICATE blocks (e.g., a chain),
//     this function returns the FIRST one (the typical leaf or single CA).
func ParseCertPEM(pemBytes []byte) (*x509.Certificate, error) {
	for {
		var b *pem.Block
		b, pemBytes = pem.Decode(pemBytes)
		if b == nil {
			return nil, errors.New("no CERTIFICATE block found in PEM data")
		}
		if b.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse certificate: %w", err)
		}
		return cert, nil
	}
}

// ParseAnyKeyPEM parses a private key from a PEM buffer and returns it as a crypto.Signer.
//
// Accepted inputs:
//   - PKCS#8:    Type "PRIVATE KEY" (unencrypted)  → Ed25519 only (project policy).
//   - Encrypted PKCS#8: Type "ENCRYPTED PRIVATE KEY" → not supported (explicit error).
//   - Legacy PEM encryption ("Proc-Type: 4,ENCRYPTED") → not supported (explicit error).
//
// Rejected inputs (with clear errors):
//   - RSA/EC legacy types: "RSA PRIVATE KEY", "EC PRIVATE KEY" (use Ed25519 PKCS#8).
//   - Any non-private-key PEM types.
//
// Returns:
//   - crypto.Signer backed by an ed25519.PrivateKey if successful.
//
// Security policy:
//   - This project is Ed25519-only; other key types are rejected.
func ParseAnyKeyPEM(pemBytes []byte) (crypto.Signer, error) {
	for {
		var b *pem.Block
		b, pemBytes = pem.Decode(pemBytes)
		if b == nil {
			return nil, errors.New("no supported private key block found in PEM data")
		}

		switch b.Type {
		case "PRIVATE KEY":
			// Unencrypted PKCS#8
			keyAny, err := x509.ParsePKCS8PrivateKey(b.Bytes)
			if err != nil {
				return nil, fmt.Errorf("parse PKCS#8 private key: %w", err)
			}
			if sk, ok := keyAny.(ed25519.PrivateKey); ok {
				return sk, nil
			}
			return nil, fmt.Errorf("unsupported private key type (only Ed25519 allowed)")

		case "ENCRYPTED PRIVATE KEY":
			// Encrypted PKCS#8 requires a password; we intentionally do not support it here.
			return nil, errors.New("encrypted PKCS#8 keys are not supported by ParseAnyKeyPEM")

		case "RSA PRIVATE KEY", "EC PRIVATE KEY", "DSA PRIVATE KEY":
			// Explicitly reject non-Ed25519 legacy encodings.
			return nil, fmt.Errorf("unsupported PEM key type %q (only Ed25519 PKCS#8 is allowed)", b.Type)

		default:
			// Skip unrelated PEM blocks (e.g., CERTIFICATE, PUBLIC KEY, etc.) and keep scanning.
			continue
		}
	}
}
