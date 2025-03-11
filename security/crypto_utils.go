package security

import (
	"crypto/hmac"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/ollama/ollama/api"
	"github.com/ollama/ollama/envconfig"
	"github.com/tjfoc/gmsm/sm2"
	"github.com/tjfoc/gmsm/sm3"
	"github.com/tjfoc/gmsm/x509"
)

func SM3Hmac(key, message []byte) ([]byte, error) {
	// Create a new HMAC calculator using SM3 hash function
	h := hmac.New(sm3.New, key)
	h.Write(message)
	return h.Sum(nil), nil
}

func SM3HmacFile(key []byte, filePath string) ([]byte, error) {
	// Open the file for reading
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// Create a new HMAC calculator using SM3 hash function
	h := hmac.New(sm3.New, key)

	// Read the file in chunks and update the HMAC
	buffer := make([]byte, 64*1024) // 64KB buffer
	for {
		n, err := f.Read(buffer)
		if err != nil && err != io.EOF {
			return nil, fmt.Errorf("failed to read file: %v", err)
		}
		if n == 0 {
			break
		}

		h.Write(buffer[:n])
	}

	// Compute and return the HMAC result
	hmacSum := h.Sum(nil)
	return hmacSum, nil
}

func GetHmacKey() ([]byte, bool) {
	// Get the HMAC key file path from environment configuration
	hmacKeyFile := envconfig.HMACKey()
	if hmacKeyFile == "" {
		return []byte("my_secret_key"), false
	}

	// Load the HMAC key from the file
	hmacKey, err := os.ReadFile(hmacKeyFile)
	if err != nil {
		return []byte("my_secret_key"), false
	}
	return hmacKey, true
}

// LoadSM2PrivateKey loads and parses the SM2 private key
func LoadSM2PrivateKey() (*sm2.PrivateKey, error) {
	// Get the SM2 key file path from environment configuration
	sm2File := envconfig.SM2Key()
	if sm2File == "" {
		return nil, fmt.Errorf("SM2 key file not configured")
	}

	// Read the key file
	keyBytes, err := os.ReadFile(sm2File)
	if err != nil {
		return nil, fmt.Errorf("failed to read SM2 key file: %v", err)
	}

	// Decode the PEM format
	block, _ := pem.Decode(keyBytes)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("failed to decode PEM block containing private key")
	}

	// Parse the SM2 private key
	privKey, err := x509.ParsePKCS8PrivateKey(block.Bytes, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SM2 private key: %v", err)
	}

	return privKey, nil
}

// LoadSecurityConfig checks the validity of security-related configurations
func LoadSecurityConfig() (string, string, *sm2.PrivateKey, error) {
	// Get SSL certificate and key file paths from environment configuration
	certFile := envconfig.SSLCert()
	keyFile := envconfig.SSLKey()
	if (certFile == "" && keyFile != "") || (certFile != "" && keyFile == "") {
		return "", "", nil, fmt.Errorf("SSL requires both cert and key")
	}

	// Check if the SM2 key file is a valid SM2 file
	sm2File := envconfig.SM2Key()
	var sm2Key *sm2.PrivateKey = nil
	if sm2File != "" {
		var err error
		sm2Key, err = LoadSM2PrivateKey()
		if err != nil {
			return "", "", nil, err
		}
	}
	return certFile, keyFile, sm2Key, nil
}

// IsGMSSLCertFile checks if the certificate is a GM SSL certificate
func IsGMSSLCertFile(certFile string) bool {
	if certFile == "" {
		return false
	}
	data, _ := os.ReadFile(certFile)
	block, _ := pem.Decode(data)
	if block == nil {
		return false
	}

	// Detect the certificate type
	if strings.Contains(block.Type, "SM2") {
		return true
	}
	if strings.Contains(block.Type, "CERTIFICATE") {
		cert, _ := x509.ParseCertificate(block.Bytes)
		return cert.SignatureAlgorithm == x509.SM2WithSM3
	}
	return false
}

func SignResponse(sm2Key *sm2.PrivateKey, sm3Sum []byte, signatory string, resp *api.ChatResponse) error {
	// Sign the "SM3 hex value + timestamp + signatory" using SM2
	sm3Hex := fmt.Sprintf("%x", sm3Sum)
	timeStr := time.Now().UTC().String()
	signData := append([]byte(sm3Hex), []byte(timeStr)...)
	signData = append(signData, []byte(signatory)...)

	value, err := sm2Key.Sign(rand.Reader, signData, nil)
	if err == nil {
		resp.Signature = api.Signature{
			Time:      timeStr,
			Value:     fmt.Sprintf("%x", value),
			SM3:       sm3Hex,
			Signatory: signatory,
		}
		slog.Info("signPlain in hex", "hex", fmt.Sprintf("%x", signData))
		slog.Info("signValue in hex", "hex", fmt.Sprintf("%x", value), " len=", len(value))
		slog.Info("*****test sign :", "bool", sm2Key.Verify(signData, value))
	} else {
		slog.Error("SM2 signature error", "error", err)
	}
	return err
}