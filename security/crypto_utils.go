package security

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/ollama/ollama/api"
	"github.com/ollama/ollama/envconfig"
	"github.com/sansec-ai/gmsm/gmtls"
	"golang.org/x/crypto/pkcs12"
)

type Crypto interface {
	Hmac(message []byte) ([]byte, error)
	Sign(message []byte) ([]byte, error)
	Verify(message []byte, signed []byte) bool
	HmacFile(filePath string) ([]byte, error)
	Encrypt(plaintext []byte) ([]byte, error)
	Decrypt(ciphertext []byte) ([]byte, error)
}

// 检查安全相关配置的有效性
func LoadSecurityConfig() ([]tls.Certificate, []gmtls.Certificate, Crypto, error) {
	crypto, err := NewCrypto()
	if err != nil {
		return nil, nil, nil, err
	}

	certFile := envconfig.SSLPfx()
	if certFile == "" {
		return nil, nil, crypto, nil
	}
	passwd := envconfig.SSLPfxPass()

	rsaCerts, err := loadPFXCert_RSA(certFile, passwd)
	if rsaCerts != nil || err == nil {
		return rsaCerts, nil, crypto, nil
	}

	// 加载rsa证书错误，尝试GM证书加载
	slog.Warn("Failed to load RSA certificate, retry load GM certificate", "error", err)

	signCert, err := loadPFXCert_SM2(certFile, passwd)
	if err != nil {
		slog.Error("Failed to load GM certificate ", "error", err)
		return nil, nil, nil, err
	}
	encCert, err := loadPFXCert_SM2(envconfig.SSLPfxEnc(), envconfig.SSLPfxEncPass())
	if err != nil {
		slog.Error("Failed to load GM Encryption certificate ", "error", err)
		return nil, nil, nil, err
	}
	return nil, []gmtls.Certificate{*signCert, *encCert}, crypto, nil
}

func loadPFXCert_RSA(pfxFile string, password string) ([]tls.Certificate, error) {
	pfx_data, err := os.ReadFile(pfxFile)
	if err != nil {
		return nil, err
	}

	privateKey, cert, err := pkcs12.Decode(pfx_data, password)
	if err != nil {
		return nil, err
	}
	// 构建tls.Certificate
	tlsCert := tls.Certificate{
		Certificate: [][]byte{cert.Raw},
		PrivateKey:  privateKey,
		Leaf:        cert,
	}
	return []tls.Certificate{tlsCert}, nil
}

func loadPFXCert_SM2(pfxFile string, password string) (*gmtls.Certificate, error) {
	pfxData, err := os.ReadFile(pfxFile)
	if err != nil {
		return nil, err
	}

	cert, privateKey, err := ParsePkcs12Cert(password, pfxData)
	if err != nil {
		return nil, err
	}

	// 构建 gmtls.Certificate
	gmCert := gmtls.Certificate{
		Certificate: [][]byte{cert.Raw},
		PrivateKey:  privateKey,
		Leaf:        cert,
	}
	return &gmCert, nil
}

func SignResponse(crypto Crypto, sm3Sum []byte, signatory string, resp *api.ChatResponse) error {

	// 对"sm3 hex值+时间戳+签名人"进行sm2签名
	sm3Hex := fmt.Sprintf("%x", sm3Sum)
	timeStr := time.Now().UTC().String()
	signData := append([]byte(sm3Hex), []byte(timeStr)...)
	signData = append(signData, []byte(signatory)...)
	// signData := []byte("test111")

	value, err := crypto.Sign(signData)
	if err != nil {
		slog.Error("sm2 signature error", "error", err)
		return err
	}

	if value == nil {
		slog.Warn("输出消息未签名, 请检查私钥是否正确")
		return nil
	}

	resp.Signature = api.Signature{
		Time:      timeStr,
		Value:     fmt.Sprintf("%x", value),
		SM3:       sm3Hex,
		Signatory: signatory,
	}
	// slog.Info("signPlain in hex", "hex", fmt.Sprintf("%x", signData))
	// slog.Info("signValue in hex", "hex", fmt.Sprintf("%x", value), " len=", len(value))
	return err
}

func GetHmacKey() ([]byte, bool) {
	hmacKeyData := envconfig.HMACKey()
	if hmacKeyData == "" {
		return nil, false
	}
	return []byte(hmacKeyData), true
}
