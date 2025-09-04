package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"time"
)

func main() {
	// Parse command line arguments
	caCertFile := flag.String("ca-cert", "", "Path to PEM encoded CA certificate file")
	caKeyFile := flag.String("ca-key", "", "Path to PEM encoded CA private key file")
	flag.Parse()

	if *caCertFile == "" || *caKeyFile == "" {
		log.Fatal("Usage: go run main.go -ca-cert <ca-cert.pem> -ca-key <ca-key.pem>")
	}

	// Load the original CA certificate and key
	originalCA, originalCAKey, err := loadCA(*caCertFile, *caKeyFile)
	if err != nil {
		log.Fatalf("Failed to load CA: %v", err)
	}

	fmt.Println("✓ Loaded original CA certificate and key")

	// Generate new CA with critical basic constraints
	newCA, newCAKey, err := generateNewCA(originalCA, originalCAKey)
	if err != nil {
		log.Fatalf("Failed to generate new CA: %v", err)
	}

	fmt.Println("✓ Generated new CA with critical basic constraints")

	// Save the new CA to a file for inspection
	err = saveCAToFile(newCA, "new-ca.pem")
	if err != nil {
		log.Printf("Warning: Failed to save new CA to file: %v", err)
	} else {
		fmt.Println("✓ Saved new CA to new-ca.pem for inspection")
	}

	// Generate server certificate using the new CA
	serverCert, serverKey, err := generateServerCert(newCA, newCAKey)
	if err != nil {
		log.Fatalf("Failed to generate server certificate: %v", err)
	}

	fmt.Println("✓ Generated server certificate for localhost")

	// Start web server with the new certificate
	server := startWebServer(serverCert, serverKey)
	defer server.Close()

	fmt.Println("✓ Web server started on https://localhost:8443")

	// Test client compatibility with both CAs
	fmt.Println("\n=== Testing CA Compatibility ===")

	// Test 1: Client with original CA (should fail)
	fmt.Println("\nTest 1: Client with original CA")
	err = testClientCompatibility(originalCA, "Original CA")
	if err != nil {
		fmt.Printf("❌ Expected failure with original CA: %v\n", err)
	} else {
		fmt.Println("⚠ Unexpected success with original CA")
	}

	// Test 2: Client with new CA (should succeed)
	fmt.Println("\nTest 2: Client with new CA")
	err = testClientCompatibility(newCA, "New CA")
	if err != nil {
		log.Fatalf("❌ Unexpected failure with new CA: %v", err)
	}

	fmt.Println("\n🎉 Success! The regenerated CA with critical basic constraints is NOT compatible with clients using the original CA.")
	fmt.Println("This demonstrates that changing basic constraints to critical breaks backward compatibility.")
}

func loadCA(certFile, keyFile string) (*x509.Certificate, *rsa.PrivateKey, error) {
	// Load CA certificate
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read CA certificate: %v", err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, nil, fmt.Errorf("failed to decode CA certificate PEM")
	}

	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse CA certificate: %v", err)
	}

	// Load CA private key
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read CA private key: %v", err)
	}

	block, _ = pem.Decode(keyPEM)
	if block == nil {
		return nil, nil, fmt.Errorf("failed to decode CA private key PEM")
	}

	var caKey *rsa.PrivateKey

	// Try PKCS#1 first
	caKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		// Try PKCS#8
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse CA private key (tried PKCS#1 and PKCS#8): %v", err)
		}

		// Type assert to RSA private key
		var ok bool
		caKey, ok = key.(*rsa.PrivateKey)
		if !ok {
			return nil, nil, fmt.Errorf("CA private key is not an RSA key")
		}
	}

	return caCert, caKey, nil
}

func generateNewCA(originalCA *x509.Certificate, originalCAKey *rsa.PrivateKey) (*x509.Certificate, *rsa.PrivateKey, error) {
	// Create a new CA certificate identical to the original except for critical basic constraints
	// Use the same serial number as the original
	newCATemplate := &x509.Certificate{
		SerialNumber:          originalCA.SerialNumber,
		Subject:               originalCA.Subject,
		NotBefore:             originalCA.NotBefore,
		NotAfter:              originalCA.NotAfter,
		IsCA:                  true,
		ExtKeyUsage:           originalCA.ExtKeyUsage,
		KeyUsage:              originalCA.KeyUsage,
		BasicConstraintsValid: true,
		// Copy other relevant fields from original CA
		Issuer:             originalCA.Issuer,
		SignatureAlgorithm: originalCA.SignatureAlgorithm,
		PublicKeyAlgorithm: originalCA.PublicKeyAlgorithm,
	}

	// Create the new CA certificate (self-signed)
	newCABytes, err := x509.CreateCertificate(rand.Reader, newCATemplate, newCATemplate, &originalCAKey.PublicKey, originalCAKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create new CA certificate: %v", err)
	}

	newCA, err := x509.ParseCertificate(newCABytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse new CA certificate: %v", err)
	}

	// Verify that the basic constraints are critical
	if len(newCA.Extensions) > 0 {
		for _, ext := range newCA.Extensions {
			if len(ext.Id) == 4 && ext.Id[0] == 2 && ext.Id[1] == 5 && ext.Id[2] == 29 && ext.Id[3] == 19 {
				// This is the basicConstraints extension
				if ext.Critical {
					fmt.Println("✓ Verified: Basic constraints are critical in the new CA")
				} else {
					fmt.Println("⚠ Warning: Basic constraints are not critical in the new CA")
				}
				break
			}
		}
	}

	return newCA, originalCAKey, nil
}

func generateServerCert(ca *x509.Certificate, caKey *rsa.PrivateKey) (*x509.Certificate, *rsa.PrivateKey, error) {
	// Generate RSA key pair for server
	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate server key: %v", err)
	}

	// Create server certificate template
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial number: %v", err)
	}

	serverTemplate := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "localhost",
		},
		DNSNames:    []string{"localhost"},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(1, 0, 0), // 1 year validity
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}

	// Create the server certificate
	serverCertBytes, err := x509.CreateCertificate(rand.Reader, serverTemplate, ca, &serverKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create server certificate: %v", err)
	}

	serverCert, err := x509.ParseCertificate(serverCertBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse server certificate: %v", err)
	}

	return serverCert, serverKey, nil
}

func startWebServer(cert *x509.Certificate, key *rsa.PrivateKey) *http.Server {
	// Create TLS certificate
	tlsCert := tls.Certificate{
		Certificate: [][]byte{cert.Raw},
		PrivateKey:  key,
	}

	// Configure TLS
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	}

	// Create server
	server := &http.Server{
		Addr:      ":8443",
		TLSConfig: tlsConfig,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			w.Write([]byte("Hello from regenerated CA server!"))
		}),
	}

	// Start server in goroutine
	go func() {
		if err := server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			log.Printf("Server error: %v", err)
		}
	}()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	return server
}

func testClientCompatibility(ca *x509.Certificate, caName string) error {
	// Create a certificate pool with the specified CA
	caPool := x509.NewCertPool()
	caPool.AddCert(ca)

	// Configure TLS client
	tlsConfig := &tls.Config{
		RootCAs: caPool,
	}

	// Create HTTP client
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
		Timeout: 10 * time.Second,
	}

	// Make request to the server
	resp, err := client.Get("https://localhost:8443")
	if err != nil {
		return fmt.Errorf("client request failed: %v", err)
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %v", err)
	}

	fmt.Printf("✓ Client received response: %s\n", string(body))

	return nil
}

func saveCAToFile(cert *x509.Certificate, filename string) error {
	// Create PEM block
	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}

	// Write to file
	err := os.WriteFile(filename, pem.EncodeToMemory(block), 0644)
	if err != nil {
		return fmt.Errorf("failed to write CA certificate to file: %v", err)
	}

	return nil
}
