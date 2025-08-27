# mintls

![Status Badge](https://img.shields.io/badge/Status-WIP-red)

**mTLS-first building blocks for Go services.**
Opinionated, Ed25519-only PKI with strict defaults. Not a web framework.

---

## Project Status

This project is in **active design**. No code is published yet—APIs shown below are **proposed** and subject to change.
Contributions and design feedback are welcome.

---

## What is mintls?

`mintls` helps you spin up Go services that are **mTLS-secure by default**, without external tools like OpenSSL. It provides a minimal, composable toolkit:

* **PKI (Ed25519-only):** create a root CA and issue server/client certs with modern, safe defaults.
* **Trust bundles:** load CA certs, optional denylist, with simple hot-reload hooks.
* **Caddy integration:** generate certs and trust files that plug directly into [Caddy](https://caddyserver.com/) for TLS/mTLS enforcement.
* **Optional TLS helpers:** build `*tls.Config` for Go servers/clients (for east–west mTLS, not edge).
* **Testkit:** generate in-memory CAs and perform loopback mTLS handshakes in `go test`.

---

## When should you use mintls?

Use `mintls` if you want:

* To secure **internal Go microservices** with mTLS-only connections.
* To issue and rotate short-lived client certs for **IoT devices or agents**.
* To generate PKI material for **Caddy edge servers**, enforcing TLS 1.3 + mTLS with hot reload.
* A **Go-native test harness** for mTLS handshakes.

Not a good fit if:

* You need RSA/ECDSA compatibility (Ed25519 only).
* You want a full authN/authZ system (no OAuth, JWTs, passwords).
* You want public ACME/Let’s Encrypt integration (use Caddy directly).

---

## What mintls is **not**

* Not a general-purpose crypto toolkit.
* Not a server framework or router.
* Not a replacement for ACME/Let’s Encrypt.
* Not an authorization system.

---

## Packages

```
mintls/
  pki/       # Ed25519-only CA + leaf issuance + PEM/DER helpers
  trust/     # CA pool loader + denylist + hot-reload
  caddy/     # integration helpers + sample Caddyfile snippets
  tlsx/      # optional: build *tls.Config for east–west mTLS
  testkit/   # test helpers: in-memory CA + loopback mTLS server/client
```

### Import examples

```go
import (
  "crypto/tls"
  "crypto/x509"
  "net/http"
  "github.com/jon-ski/mintls/pki"
  "github.com/jon-ski/mintls/trust"
)
```

---

## Quick start

### 1. Generate a CA and leaf certs

```go
// Root CA (5 years)
caCert, caKey, caPair, _ := pki.CreateCA(pki.CAParams{CommonName: "Root CA"})
_ = pki.WriteCertPEM("certs/ca.crt", caPair.CertDER, 0o644)
_ = pki.WritePKCS8KeyPEM("certs/ca.key", caPair.KeyPKCS8, 0o600)

// Server leaf
_, _, srvPair, _ := pki.IssueLeaf(caCert, caKey, pki.LeafParams{
  DNS:       []string{"localhost"},
  IPs:       []net.IP{net.ParseIP("127.0.0.1")},
  ServerEKU: true,
})
_ = pki.WriteCertPEM("certs/server.crt", srvPair.CertDER, 0o644)
_ = pki.WritePKCS8KeyPEM("certs/server.key", srvPair.KeyPKCS8, 0o600)

// Client leaf
_, _, cliPair, _ := pki.IssueLeaf(caCert, caKey, pki.LeafParams{
  CommonName: "laptop",
  ClientEKU:  true,
})
```

### 2. Use with Caddy (edge mTLS)

Example Caddyfile:

```caddyfile
example.internal {
  tls {
    client_auth {
      mode require_and_verify
      trusted_ca_certs_file /etc/mintls/ca.crt
    }
  }

  reverse_proxy unix//run/myapp.sock {
    header_up X-Client-Cert-Subject {tls_client_subject}
    header_up X-Client-Cert-Serial  {tls_client_serial}
    header_up X-Client-Cert-SANs    {tls_client_san}
  }
}
```

Rotate CA by replacing `ca.crt` and reloading Caddy. Block clients by re-issuing without them, or rotate to a new CA.

### 3. East–west mTLS (optional in-app)

```go
// Trust store loads CA
pool, _ := trust.LoadPool("certs/ca.crt")

// Load server cert/key
tlsCert, _ := tls.LoadX509KeyPair("certs/server.crt", "certs/server.key")

srv := &http.Server{
  Addr:      ":8002",
  TLSConfig: tlsx.ServerTLS(tlsCert, pool),
  Handler:   myMux,
}
```

---

## Threat Model

**Covers:**

* Unauthorized clients at the transport layer.
* TLS 1.3 integrity and confidentiality.
* Hot-rotation of trust anchors.

**Not covered:**

* Key distribution and secret storage.
* Higher-layer authentication/authorization (OAuth, RBAC, etc.).
* Public HTTPS certificate management.

---

## Security defaults

* **Ed25519 only**
* **TLS 1.3 only**
* **CA validity:** 5 years
* **Leaf validity:** 397 days
* **SANs required**
* **KeyUsage/EKU:** least-privilege
* **PKCS#8 keys** (0600); certs (0644)
* **Atomic file writes**

---

## Roadmap

* **M1:** Repo skeleton + package stubs + README.
* **M2:** PKI core implementation.
* **M3:** Trust store + rotation.
* **M4:** Caddy integration docs + examples.
* **M5:** Optional `tlsx` for east–west.
* **M6:** Testkit and fuzz tests.

---

## License

Apache 2.0
