package samcrack

import (
	"crypto/des"
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

// BootKeyParser BootKey解析器
type BootKeyParser struct {
	systemPath string
}

// NewBootKeyParser 创建新的BootKey解析器
func NewBootKeyParser(systemPath string) *BootKeyParser {
	return &BootKeyParser{
		systemPath: systemPath,
	}
}

// BootKey 启动密钥结构
type BootKey struct {
	Key []byte // 16字节的BootKey
}

// ExtractBootKey 从SYSTEM文件提取BootKey
func (p *BootKeyParser) ExtractBootKey() (*BootKey, error) {
	file, err := os.Open(p.systemPath)
	if err != nil {
		return nil, fmt.Errorf("打开SYSTEM文件失败: %v", err)
	}
	defer file.Close()

	// 解析注册表hive文件结构
	hive, err := p.parseRegistryHive(file)
	if err != nil {
		return nil, err
	}

	// 查找Control\Lsa\JD键值
	bootKeyFragments, err := p.findBootKeyFragments(hive)
	if err != nil {
		return nil, err
	}

	// 重组BootKey片段
	bootKey, err := p.reconstructBootKey(bootKeyFragments)
	if err != nil {
		return nil, err
	}

	return &BootKey{Key: bootKey}, nil
}

// parseRegistryHive 解析注册表hive文件
func (p *BootKeyParser) parseRegistryHive(file *os.File) (*RegistryHive, error) {
	// 读取文件头
	header := make([]byte, 4096)
	_, err := file.Read(header)
	if err != nil {
		return nil, fmt.Errorf("读取文件头失败: %v", err)
	}

	// 验证注册表签名
	if string(header[:4]) != "regf" {
		return nil, fmt.Errorf("不是有效的注册表hive文件")
	}

	return &RegistryHive{
		File:   file,
		Header: header,
	}, nil
}

// findBootKeyFragments 查找BootKey片段
func (p *BootKeyParser) findBootKeyFragments(hive *RegistryHive) ([][]byte, error) {
	// 查找Control\Lsa\JD键值路径
	// 这里简化实现，实际需要复杂的注册表结构解析
	
	// 读取整个文件内容
	fileInfo, err := hive.File.Stat()
	if err != nil {
		return nil, err
	}

	content := make([]byte, fileInfo.Size())
	_, err = hive.File.Seek(0, io.SeekStart)
	if err != nil {
		return nil, err
	}

	_, err = hive.File.Read(content)
	if err != nil {
		return nil, err
	}

	// 查找JD键值数据（简化实现）
	// 在实际实现中，需要完整的注册表解析逻辑
	jdData, err := p.findJDValue(content)
	if err != nil {
		return nil, err
	}

	// 提取BootKey片段
	return p.extractFragments(jdData), nil
}

// findJDValue 查找JD键值数据（简化实现）
func (p *BootKeyParser) findJDValue(content []byte) ([]byte, error) {
	// 在实际实现中，需要解析注册表单元结构
	// 这里返回模拟数据用于演示
	
	// 模拟JD键值数据（包含BootKey片段）
	// 实际实现需要根据注册表结构定位
	jdData := make([]byte, 64)
	
	// 填充模拟的BootKey片段数据
	for i := 0; i < 8; i++ {
		fragment := make([]byte, 4)
		binary.LittleEndian.PutUint32(fragment, uint32(i*4))
		copy(jdData[i*8:i*8+4], fragment)
	}
	
	return jdData, nil
}

// extractFragments 从JD数据中提取BootKey片段
func (p *BootKeyParser) extractFragments(jdData []byte) [][]byte {
	fragments := make([][]byte, 8)
	
	// 提取8个4字节片段
	for i := 0; i < 8; i++ {
		start := i * 8
		fragments[i] = jdData[start : start+4]
	}
	
	return fragments
}

// reconstructBootKey 重组BootKey片段
func (p *BootKeyParser) reconstructBootKey(fragments [][]byte) ([]byte, error) {
	if len(fragments) != 8 {
		return nil, fmt.Errorf("需要8个BootKey片段，实际得到%d个", len(fragments))
	}

	// 按特定顺序重组片段
	bootKey := make([]byte, 16)
	
	// BootKey重组顺序（微软私有规则）
	reorder := []int{0, 1, 2, 3, 4, 5, 6, 7}
	
	for i, idx := range reorder {
		if idx < len(fragments) {
			copy(bootKey[i*2:i*2+2], fragments[idx][:2])
		}
	}

	// 应用DES解密（简化实现）
	decryptedKey, err := p.decryptBootKey(bootKey)
	if err != nil {
		return nil, err
	}

	return decryptedKey, nil
}

// decryptBootKey 解密BootKey
func (p *BootKeyParser) decryptBootKey(encryptedKey []byte) ([]byte, error) {
	// 简化实现，实际需要完整的DES解密逻辑
	// 包括奇偶校验调整等
	
	if len(encryptedKey) != 16 {
		return nil, fmt.Errorf("加密的BootKey长度必须为16字节")
	}

	// 使用前8字节作为DES密钥（简化实现）
	key := encryptedKey[:8]
	
	// 调整奇偶校验（简化）
	adjustedKey := p.adjustParity(key)
	
	// 创建DES密码块
	block, err := des.NewCipher(adjustedKey)
	if err != nil {
		return nil, err
	}

	// 解密后8字节数据（简化实现）
	ciphertext := encryptedKey[8:]
	plaintext := make([]byte, 8)
	block.Decrypt(plaintext, ciphertext)
	
	// 组合成完整的BootKey
	decryptedKey := make([]byte, 16)
	copy(decryptedKey[:8], adjustedKey)
	copy(decryptedKey[8:], plaintext)
	
	return decryptedKey, nil
}

// adjustParity 调整DES密钥的奇偶校验
func (p *BootKeyParser) adjustParity(key []byte) []byte {
	adjusted := make([]byte, len(key))
	copy(adjusted, key)
	
	for i := 0; i < len(adjusted); i++ {
		// 计算奇偶位
		parity := byte(0)
		for j := 0; j < 7; j++ {
			if (adjusted[i]>>j)&1 == 1 {
				parity ^= 1
			}
		}
		
		// 设置奇偶位
		if parity == 1 {
			adjusted[i] |= 0x01
		} else {
			adjusted[i] &^= 0x01
		}
	}
	
	return adjusted
}

// RegistryHive 注册表hive结构
type RegistryHive struct {
	File   *os.File
	Header []byte
}