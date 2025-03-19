//go:build hsm && cgo

package security

///
import (
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"os"
	"strconv"

	"github.com/ollama/ollama/envconfig"
	"github.com/tjfoc/gmsm/sm3"
)

type HSMCrypto struct {
	sm2KeyIndex uint32
	hmacKey     []byte
}

func NewCrypto() (Crypto, error) {
	// 获取环境变量中的密钥索引
	keyIndex, err := strconv.Atoi(envconfig.SM2Key())
	if err != nil {
		return nil, fmt.Errorf("SM2_KEY_INDEX not found")
	}

	// 添加边界检查
	const minKeyIndex = 0
	const maxKeyIndex = 99
	if keyIndex < minKeyIndex || keyIndex > maxKeyIndex {
		return nil, fmt.Errorf("无效的OLLAMA_SM2_KEY值 %d，有效范围是 %d-%d", keyIndex, minKeyIndex, maxKeyIndex)
	}

	hmacKey, _ := GetHmacKey()
	if len(hmacKey) != 16 {
		// 未配置环境变量，返回错误
		return nil, fmt.Errorf("HMAC密钥未配置，或者不是16字节")
	}

	// 从环境变量获取SM4密钥
	sm4Key := []byte(envconfig.SM4Key())
	if len(sm4Key) != 16 {
		return nil, errors.New("SM4密钥未配置，或者不是16字节")
	}

	return &HSMCrypto{uint32(keyIndex), hmacKey}, nil
}

func (c *HSMCrypto) Hmac(message []byte) ([]byte, error) {
	handler, err := SDF_OpenDevice()
	if err != nil {
		return nil, err
	}
	session, err := SDF_OpenSession(handler)
	if err != nil {
		return nil, err
	}
	defer SDF_CloseSession(session)
	defer SDF_CloseDevice(handler)

	keyHandle, err := SDF_ImportKey(session, c.hmacKey)
	if err != nil {
		return nil, err
	}
	defer SDF_DestroyKey(session, keyHandle)

	pucMac, err := SDF_HMAC(session, keyHandle, SGD_SM3, message)
	if err != nil {
		return nil, fmt.Errorf("计算HMAC失败: %v", err)
	}
	return pucMac, nil
}

func (c *HSMCrypto) HmacFile(filePath string) ([]byte, error) {
	handler, err := SDF_OpenDevice()
	if err != nil {
		return nil, err
	}
	session, err := SDF_OpenSession(handler)
	if err != nil {
		return nil, err
	}
	defer SDF_CloseSession(session)
	defer SDF_CloseDevice(handler)

	keyHandle, err := SDF_ImportKey(session, c.hmacKey)
	if err != nil {
		return nil, err
	}
	defer SDF_DestroyKey(session, keyHandle)

	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	hash := sm3.New()
	// 逐块读取文件并更新HMAC
	buffer := make([]byte, 64*1024) // 64KB的缓冲区
	for {
		n, err := f.Read(buffer)
		if err != nil && err != io.EOF {
			return nil, fmt.Errorf("读取文件失败: %v", err)
		}
		if n == 0 {
			break
		}

		hash.Write(buffer[:n])
	}
	hashSum := hash.Sum(nil)
	pucMac, err := SDF_HMAC(session, keyHandle, SGD_SM3, hashSum)
	if err != nil {
		return nil, fmt.Errorf("计算HMAC失败: %v", err)
	}
	return pucMac, nil
}

func (c *HSMCrypto) Sign(message []byte) ([]byte, error) {
	handler, err := SDF_OpenDevice()
	if err != nil {
		return nil, err
	}
	session, err := SDF_OpenSession(handler)
	if err != nil {
		return nil, err
	}
	defer SDF_CloseSession(session)
	defer SDF_CloseDevice(handler)
	// 导出公钥
	pubkey, err := SDF_ExportSignPublicKey_ECC(session, c.sm2KeyIndex)
	if err != nil {
		return nil, err
	}
	// hash公钥预处理
	hashRes, err := SDF_Hash(session, SGD_SM3, pubkey, []byte("1234567812345678"), message)
	if err != nil {
		log.Println(err)
		return nil, err
	}
	// 内部密钥签名
	ecc, err := SDF_InternalSign_ECC(session, c.sm2KeyIndex, hashRes)
	if err != nil {
		log.Println(err)
		return nil, err
	}
	toGo := convertECCSignatureToGo(ecc)
	return asn1.Marshal(toGo)
}

func (c *HSMCrypto) Verify(message []byte, signed []byte) bool {
	// HSM模块不需要后端验签
	return false
}

func (c *HSMCrypto) Encrypt(plaintext []byte) ([]byte, error) {
	slog.Info("HSM Encrypt ", "Key:", os.Getenv("OLLAMA_SM4_KEY"), "plaintext", plaintext)
	handler, err := SDF_OpenDevice()
	if err != nil {
		return nil, err
	}
	defer SDF_CloseDevice(handler)

	session, err := SDF_OpenSession(handler)
	if err != nil {
		return nil, err
	}
	defer SDF_CloseSession(session)
	sm4Key, err := LoadSM4Key(session)
	if err != nil {
		return nil, err
	}

	// 生成IV
	iv, err := SDF_GenerateRandom(session, 16) // SM4块大小16字节
	if err != nil {
		return nil, fmt.Errorf("生成IV失败: %v", err)
	}

	// 执行加密
	ciphertext, err := SDF_Encrypt(
		session,
		sm4Key,       // 使用SM4密钥句柄
		SGD_SMS4_CBC, // 算法标识
		iv,
		plaintext,
	)
	if err != nil {
		return nil, fmt.Errorf("加密失败: %v", err)
	}

	return append(iv, ciphertext...), nil
}

func (c *HSMCrypto) Decrypt(ciphertext []byte) ([]byte, error) {
	slog.Info("HSM Decrypt ", "Key:", os.Getenv("OLLAMA_SM4_KEY"), "ciphertext", ciphertext)
	handler, err := SDF_OpenDevice()
	if err != nil {
		return nil, err
	}
	defer SDF_CloseDevice(handler)

	session, err := SDF_OpenSession(handler)
	if err != nil {
		return nil, err
	}
	defer SDF_CloseSession(session)
	sm4Key, err := LoadSM4Key(session)
	if err != nil {
		return nil, err
	}

	// 分离IV和密文
	if len(ciphertext) < 16 {
		return nil, errors.New("无效密文格式")
	}
	iv := ciphertext[:16]
	actualCipher := ciphertext[16:]

	// 执行解密
	plaintext, err := SDF_Decrypt(
		session,
		sm4Key,       // 使用SM4密钥句柄
		SGD_SMS4_CBC, // 算法标识
		iv,
		actualCipher,
	)
	if err != nil {
		return nil, fmt.Errorf("解密失败: %v", err)
	}

	return plaintext, nil
}

func LoadSM4Key(session CTypeSGDHandle) (CTypeSGDHandle, error) {
	// 从环境变量获取SM4密钥
	sm4Key := []byte(os.Getenv("OLLAMA_SM4_KEY"))
	if len(sm4Key) != 16 {
		return nil, errors.New("SM4密钥必须为16字节")
	}

	// 导入SM4密钥
	keyHandle, err := SDF_ImportKey(session, sm4Key)
	if err != nil {
		return nil, fmt.Errorf("导入SM4密钥失败: %v", err)
	}
	return keyHandle, nil
}
