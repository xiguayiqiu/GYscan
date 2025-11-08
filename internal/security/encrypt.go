package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/sirupsen/logrus"
)

// Encryptor 加密器接口
type Encryptor interface {
	Encrypt(data []byte) ([]byte, error)
	Decrypt(encryptedData []byte) ([]byte, error)
}

// AESEncryptor AES加密实现
type AESEncryptor struct {
	key []byte
}

// NewAESEncryptor 创建AES加密器
func NewAESEncryptor(key []byte) (*AESEncryptor, error) {
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return nil, fmt.Errorf("密钥长度必须为16、24或32字节")
	}
	return &AESEncryptor{key: key}, nil
}

// Encrypt AES加密
func (e *AESEncryptor) Encrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(e.key)
	if err != nil {
		return nil, err
	}

	// 创建GCM模式
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// 创建随机nonce
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// 加密数据
	ciphertext := aesGCM.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

// Decrypt AES解密
func (e *AESEncryptor) Decrypt(encryptedData []byte) ([]byte, error) {
	block, err := aes.NewCipher(e.key)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := aesGCM.NonceSize()
	if len(encryptedData) < nonceSize {
		return nil, fmt.Errorf("加密数据太短")
	}

	nonce, ciphertext := encryptedData[:nonceSize], encryptedData[nonceSize:]
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// RSAEncryptor RSA加密实现
type RSAEncryptor struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
}

// NewRSAEncryptor 创建RSA加密器
func NewRSAEncryptor(privateKeyPEM, publicKeyPEM string) (*RSAEncryptor, error) {
	encryptor := &RSAEncryptor{}

	// 解析私钥
	if privateKeyPEM != "" {
		block, _ := pem.Decode([]byte(privateKeyPEM))
		if block == nil {
			return nil, fmt.Errorf("私钥格式错误")
		}

		privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		encryptor.privateKey = privateKey
	}

	// 解析公钥
	if publicKeyPEM != "" {
		block, _ := pem.Decode([]byte(publicKeyPEM))
		if block == nil {
			return nil, fmt.Errorf("公钥格式错误")
		}

		publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		encryptor.publicKey = publicKey.(*rsa.PublicKey)
	}

	return encryptor, nil
}

// Encrypt RSA加密
func (e *RSAEncryptor) Encrypt(data []byte) ([]byte, error) {
	if e.publicKey == nil {
		return nil, fmt.Errorf("公钥未设置")
	}

	hash := sha256.New()
	ciphertext, err := rsa.EncryptOAEP(hash, rand.Reader, e.publicKey, data, nil)
	if err != nil {
		return nil, err
	}

	return ciphertext, nil
}

// Decrypt RSA解密
func (e *RSAEncryptor) Decrypt(encryptedData []byte) ([]byte, error) {
	if e.privateKey == nil {
		return nil, fmt.Errorf("私钥未设置")
	}

	hash := sha256.New()
	plaintext, err := rsa.DecryptOAEP(hash, rand.Reader, e.privateKey, encryptedData, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// TrafficEncryptor 流量加密器
type TrafficEncryptor struct {
	encryptor Encryptor
}

// NewTrafficEncryptor 创建流量加密器
func NewTrafficEncryptor(encryptor Encryptor) *TrafficEncryptor {
	return &TrafficEncryptor{encryptor: encryptor}
}

// EncryptTraffic 加密网络流量
func (t *TrafficEncryptor) EncryptTraffic(data []byte) ([]byte, error) {
	logrus.Debug("[GYscan] 加密网络流量")
	
	encrypted, err := t.encryptor.Encrypt(data)
	if err != nil {
		logrus.Errorf("[GYscan] 流量加密失败: %v", err)
		return nil, err
	}

	// Base64编码便于传输
	encoded := base64.StdEncoding.EncodeToString(encrypted)
	return []byte(encoded), nil
}

// DecryptTraffic 解密网络流量
func (t *TrafficEncryptor) DecryptTraffic(encryptedData []byte) ([]byte, error) {
	logrus.Debug("[GYscan] 解密网络流量")

	// Base64解码
	encoded, err := base64.StdEncoding.DecodeString(string(encryptedData))
	if err != nil {
		logrus.Errorf("[GYscan] Base64解码失败: %v", err)
		return nil, err
	}

	decrypted, err := t.encryptor.Decrypt(encoded)
	if err != nil {
		logrus.Errorf("[GYscan] 流量解密失败: %v", err)
		return nil, err
	}

	return decrypted, nil
}

// GenerateRandomKey 生成随机密钥
func GenerateRandomKey(size int) ([]byte, error) {
	key := make([]byte, size)
	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}
	return key, nil
}

// GenerateRSAKeyPair 生成RSA密钥对
func GenerateRSAKeyPair(bits int) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, err
	}
	return privateKey, &privateKey.PublicKey, nil
}

// EncryptFile 加密文件
func EncryptFile(filePath string, encryptor Encryptor) error {
	logrus.Infof("[GYscan] 加密文件: %s", filePath)

	// 读取文件内容
	data, err := os.ReadFile(filePath)
	if err != nil {
		logrus.Errorf("[GYscan] 读取文件失败: %v", err)
		return err
	}

	// 加密数据
	encryptedData, err := encryptor.Encrypt(data)
	if err != nil {
		logrus.Errorf("[GYscan] 文件加密失败: %v", err)
		return err
	}

	// 写回加密文件
	err = os.WriteFile(filePath+".enc", encryptedData, 0644)
	if err != nil {
		logrus.Errorf("[GYscan] 写入加密文件失败: %v", err)
		return err
	}

	logrus.Info("[GYscan] 文件加密完成")
	return nil
}

// DecryptFile 解密文件
func DecryptFile(filePath string, encryptor Encryptor) error {
	logrus.Infof("[GYscan] 解密文件: %s", filePath)

	// 读取加密文件
	encryptedData, err := os.ReadFile(filePath)
	if err != nil {
		logrus.Errorf("[GYscan] 读取加密文件失败: %v", err)
		return err
	}

	// 解密数据
	decryptedData, err := encryptor.Decrypt(encryptedData)
	if err != nil {
		logrus.Errorf("[GYscan] 文件解密失败: %v", err)
		return err
	}

	// 写回解密文件（移除.enc后缀）
	outputPath := strings.TrimSuffix(filePath, ".enc")
	err = os.WriteFile(outputPath, decryptedData, 0644)
	if err != nil {
		logrus.Errorf("[GYscan] 写入解密文件失败: %v", err)
		return err
	}

	logrus.Info("[GYscan] 文件解密完成")
	return nil
}