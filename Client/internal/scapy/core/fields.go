package core

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// Field 字段接口定义
type Field interface {
	Marshal() ([]byte, error)    // 序列化为字节
	Unmarshal(data []byte) error // 从字节反序列化
	Size() int                   // 字段大小（字节）
	Default() interface{}        // 默认值
	Set(value interface{}) error // 设置值
	Get() interface{}            // 获取值
	String() string              // 字符串表示
}

// BaseField 基础字段实现
type BaseField struct {
	name         string      // 字段名称
	size         int         // 字段大小
	defaultValue interface{} // 默认值
	value        interface{} // 当前值
}

// NewBaseField 创建基础字段
func NewBaseField(name string, size int, defaultValue interface{}) *BaseField {
	return &BaseField{
		name:         name,
		size:         size,
		defaultValue: defaultValue,
		value:        defaultValue,
	}
}

// Marshal 序列化（基础实现，子类需要重写）
func (bf *BaseField) Marshal() ([]byte, error) {
	return nil, fmt.Errorf("BaseField does not support direct marshaling")
}

// Unmarshal 反序列化（基础实现，子类需要重写）
func (bf *BaseField) Unmarshal(data []byte) error {
	return fmt.Errorf("BaseField does not support direct unmarshaling")
}

// Size 获取字段大小
func (bf *BaseField) Size() int {
	return bf.size
}

// Default 获取默认值
func (bf *BaseField) Default() interface{} {
	return bf.defaultValue
}

// Set 设置值
func (bf *BaseField) Set(value interface{}) error {
	bf.value = value
	return nil
}

// Get 获取值
func (bf *BaseField) Get() interface{} {
	return bf.value
}

// String 字符串表示
func (bf *BaseField) String() string {
	return fmt.Sprintf("%s: %v", bf.name, bf.value)
}

// ===== 具体字段类型实现 =====

// ByteField 字节字段
type ByteField struct {
	*BaseField
}

// NewByteField 创建字节字段
func NewByteField(name string, defaultValue byte) *ByteField {
	return &ByteField{
		BaseField: NewBaseField(name, 1, defaultValue),
	}
}

// Marshal 序列化字节字段
func (bf *ByteField) Marshal() ([]byte, error) {
	if bf.value == nil {
		return []byte{bf.defaultValue.(byte)}, nil
	}
	return []byte{bf.value.(byte)}, nil
}

// Unmarshal 反序列化字节字段
func (bf *ByteField) Unmarshal(data []byte) error {
	if len(data) < 1 {
		return fmt.Errorf("insufficient data for ByteField")
	}
	bf.value = data[0]
	return nil
}

// Uint16Field 16位无符号整数字段
type Uint16Field struct {
	*BaseField
	byteOrder binary.ByteOrder
}

// NewUint16Field 创建16位无符号整数字段
func NewUint16Field(name string, defaultValue uint16, byteOrder binary.ByteOrder) *Uint16Field {
	return &Uint16Field{
		BaseField: NewBaseField(name, 2, defaultValue),
		byteOrder: byteOrder,
	}
}

// Marshal 序列化Uint16字段
func (uf *Uint16Field) Marshal() ([]byte, error) {
	var value uint16
	if uf.value == nil {
		value = uf.defaultValue.(uint16)
	} else {
		value = uf.value.(uint16)
	}

	data := make([]byte, 2)
	uf.byteOrder.PutUint16(data, value)
	return data, nil
}

// Unmarshal 反序列化Uint16字段
func (uf *Uint16Field) Unmarshal(data []byte) error {
	if len(data) < 2 {
		return fmt.Errorf("insufficient data for Uint16Field")
	}
	uf.value = uf.byteOrder.Uint16(data)
	return nil
}

// Uint32Field 32位无符号整数字段
type Uint32Field struct {
	*BaseField
	byteOrder binary.ByteOrder
}

// NewUint32Field 创建32位无符号整数字段
func NewUint32Field(name string, defaultValue uint32, byteOrder binary.ByteOrder) *Uint32Field {
	return &Uint32Field{
		BaseField: NewBaseField(name, 4, defaultValue),
		byteOrder: byteOrder,
	}
}

// Marshal 序列化Uint32字段
func (uf *Uint32Field) Marshal() ([]byte, error) {
	var value uint32
	if uf.value == nil {
		value = uf.defaultValue.(uint32)
	} else {
		value = uf.value.(uint32)
	}

	data := make([]byte, 4)
	uf.byteOrder.PutUint32(data, value)
	return data, nil
}

// Unmarshal 反序列化Uint32字段
func (uf *Uint32Field) Unmarshal(data []byte) error {
	if len(data) < 4 {
		return fmt.Errorf("insufficient data for Uint32Field")
	}
	uf.value = uf.byteOrder.Uint32(data)
	return nil
}

// IPField IP地址字段
type IPField struct {
	*BaseField
}

// NewIPField 创建IP地址字段
func NewIPField(name string, defaultValue net.IP) *IPField {
	if defaultValue == nil {
		defaultValue = net.IPv4zero
	}
	return &IPField{
		BaseField: NewBaseField(name, len(defaultValue), defaultValue),
	}
}

// Marshal 序列化IP字段
func (ipf *IPField) Marshal() ([]byte, error) {
	var ip net.IP
	if ipf.value == nil {
		ip = ipf.defaultValue.(net.IP)
	} else {
		ip = ipf.value.(net.IP)
	}

	if ip == nil {
		return net.IPv4zero, nil
	}
	return ip, nil
}

// Unmarshal 反序列化IP字段
func (ipf *IPField) Unmarshal(data []byte) error {
	if len(data) < 4 {
		return fmt.Errorf("insufficient data for IPField")
	}
	ipf.value = net.IP(data)
	return nil
}

// MACField MAC地址字段
type MACField struct {
	*BaseField
}

// NewMACField 创建MAC地址字段
func NewMACField(name string, defaultValue net.HardwareAddr) *MACField {
	if defaultValue == nil {
		defaultValue = make(net.HardwareAddr, 6)
	}
	return &MACField{
		BaseField: NewBaseField(name, len(defaultValue), defaultValue),
	}
}

// Marshal 序列化MAC字段
func (mf *MACField) Marshal() ([]byte, error) {
	var mac net.HardwareAddr
	if mf.value == nil {
		mac = mf.defaultValue.(net.HardwareAddr)
	} else {
		mac = mf.value.(net.HardwareAddr)
	}

	if mac == nil {
		return make([]byte, 6), nil
	}
	return mac, nil
}

// Unmarshal 反序列化MAC字段
func (mf *MACField) Unmarshal(data []byte) error {
	if len(data) < 6 {
		return fmt.Errorf("insufficient data for MACField")
	}
	mf.value = net.HardwareAddr(data)
	return nil
}

// BytesField 字节数组字段
type BytesField struct {
	*BaseField
}

// NewBytesField 创建字节数组字段
func NewBytesField(name string, defaultValue []byte) *BytesField {
	if defaultValue == nil {
		defaultValue = []byte{}
	}
	return &BytesField{
		BaseField: NewBaseField(name, len(defaultValue), defaultValue),
	}
}

// Marshal 序列化字节数组字段
func (bf *BytesField) Marshal() ([]byte, error) {
	var data []byte
	if bf.value == nil {
		data = bf.defaultValue.([]byte)
	} else {
		data = bf.value.([]byte)
	}

	if data == nil {
		return []byte{}, nil
	}
	return data, nil
}

// Unmarshal 反序列化字节数组字段
func (bf *BytesField) Unmarshal(data []byte) error {
	bf.value = data
	return nil
}

// StringField 字符串字段
type StringField struct {
	*BaseField
}

// NewStringField 创建字符串字段
func NewStringField(name string, defaultValue string) *StringField {
	return &StringField{
		BaseField: NewBaseField(name, len(defaultValue), defaultValue),
	}
}

// Marshal 序列化字符串字段
func (sf *StringField) Marshal() ([]byte, error) {
	var str string
	if sf.value == nil {
		str = sf.defaultValue.(string)
	} else {
		str = sf.value.(string)
	}

	return []byte(str), nil
}

// Unmarshal 反序列化字符串字段
func (sf *StringField) Unmarshal(data []byte) error {
	sf.value = string(data)
	return nil
}

// BoolField 布尔字段
type BoolField struct {
	*BaseField
}

// NewBoolField 创建布尔字段
func NewBoolField(name string, defaultValue bool) *BoolField {
	return &BoolField{
		BaseField: NewBaseField(name, 1, defaultValue),
	}
}

// Marshal 序列化布尔字段
func (bf *BoolField) Marshal() ([]byte, error) {
	var value bool
	if bf.value == nil {
		value = bf.defaultValue.(bool)
	} else {
		value = bf.value.(bool)
	}

	if value {
		return []byte{1}, nil
	}
	return []byte{0}, nil
}

// Unmarshal 反序列化布尔字段
func (bf *BoolField) Unmarshal(data []byte) error {
	if len(data) < 1 {
		return fmt.Errorf("insufficient data for BoolField")
	}
	bf.value = data[0] != 0
	return nil
}

// EnumField 枚举字段
type EnumField struct {
	*BaseField
	enumMap map[string]interface{}
}

// NewEnumField 创建枚举字段
func NewEnumField(name string, defaultValue interface{}, enumMap map[string]interface{}) *EnumField {
	return &EnumField{
		BaseField: NewBaseField(name, 1, defaultValue),
		enumMap:   enumMap,
	}
}

// Marshal 序列化枚举字段
func (ef *EnumField) Marshal() ([]byte, error) {
	var value interface{}
	if ef.value == nil {
		value = ef.defaultValue
	} else {
		value = ef.value
	}

	switch v := value.(type) {
	case byte:
		return []byte{v}, nil
	case int:
		return []byte{byte(v)}, nil
	case string:
		if enumValue, ok := ef.enumMap[v]; ok {
			switch ev := enumValue.(type) {
			case byte:
				return []byte{ev}, nil
			case int:
				return []byte{byte(ev)}, nil
			default:
				return nil, fmt.Errorf("unsupported enum value type: %T", ev)
			}
		}
		return nil, fmt.Errorf("unknown enum value: %s", v)
	default:
		return nil, fmt.Errorf("unsupported value type: %T", v)
	}
}

// Unmarshal 反序列化枚举字段
func (ef *EnumField) Unmarshal(data []byte) error {
	if len(data) < 1 {
		return fmt.Errorf("insufficient data for EnumField")
	}
	ef.value = data[0]
	return nil
}

// FieldSet 字段集合
type FieldSet struct {
	fields map[string]Field
}

// NewFieldSet 创建字段集合
func NewFieldSet() *FieldSet {
	return &FieldSet{
		fields: make(map[string]Field),
	}
}

// AddField 添加字段
func (fs *FieldSet) AddField(name string, field Field) {
	fs.fields[name] = field
}

// GetField 获取字段
func (fs *FieldSet) GetField(name string) Field {
	return fs.fields[name]
}

// MarshalAll 序列化所有字段
func (fs *FieldSet) MarshalAll() ([]byte, error) {
	var result []byte

	for name, field := range fs.fields {
		data, err := field.Marshal()
		if err != nil {
			return nil, fmt.Errorf("error marshaling field %s: %v", name, err)
		}
		result = append(result, data...)
	}

	return result, nil
}

// UnmarshalAll 反序列化所有字段
func (fs *FieldSet) UnmarshalAll(data []byte) error {
	offset := 0

	for name, field := range fs.fields {
		fieldSize := field.Size()
		if offset+fieldSize > len(data) {
			return fmt.Errorf("insufficient data for field %s", name)
		}

		err := field.Unmarshal(data[offset : offset+fieldSize])
		if err != nil {
			return fmt.Errorf("error unmarshaling field %s: %v", name, err)
		}

		offset += fieldSize
	}

	return nil
}

// ParseMAC 解析MAC地址字符串
func ParseMAC(macStr string) (net.HardwareAddr, error) {
	// 清理字符串
	macStr = strings.ReplaceAll(macStr, "-", ":")
	macStr = strings.ReplaceAll(macStr, ".", ":")

	return net.ParseMAC(macStr)
}

// ParseIP 解析IP地址字符串
func ParseIP(ipStr string) net.IP {
	return net.ParseIP(ipStr)
}

// ParsePort 解析端口字符串
func ParsePort(portStr string) (uint16, error) {
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return 0, err
	}
	return uint16(port), nil
}
