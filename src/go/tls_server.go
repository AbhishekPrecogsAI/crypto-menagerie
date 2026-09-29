// tls_server.go — two TLS configs: a deliberately weak one and a hardened,
// post-quantum-hybrid one. Expected CBOM: TLS 1.0/1.1 (deprecated protocol),
// RC4/3DES cipher suites (weak), vs TLS 1.3 with X25519MLKEM768 (PQC hybrid
// key exchange). Drives the protocol/negotiation checks.
package main

import (
	"crypto/tls"
	"log"
	"net/http"
)

// weakTLS — everything you should not ship: down to TLS 1.0 with RC4/3DES.
func weakTLS() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS10, // deprecated
		MaxVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_RSA_WITH_RC4_128_SHA,        // RC4 — broken
			tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,   // 3DES — Sweet32
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		},
	}
}

// hardenedTLS — TLS 1.3 with a post-quantum hybrid key exchange group.
func hardenedTLS() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{
			tls.X25519MLKEM768, // hybrid classical + ML-KEM-768
			tls.X25519,
		},
	}
}

func main() {
	srv := &http.Server{Addr: ":8443", TLSConfig: hardenedTLS()}
	log.Fatal(srv.ListenAndServeTLS("../certs/ec-p256.pem", "../certs/ec-p256.key"))
}
