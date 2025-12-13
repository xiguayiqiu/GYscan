# Go Scapy 移植架构设计

## 总体架构

```
scapy/
├── core/           # 核心包构造系统
│   ├── packet.go   # 包基类和字段系统
│   ├── fields.go   # 字段类型定义
│   └── builder.go  # 包构建器
├── layers/         # 协议层实现
│   ├── ethernet.go # 以太网层
│   ├── ip.go       # IP层
│   ├── tcp.go      # TCP层
│   ├── udp.go      # UDP层
│   └── ...         # 其他协议层
├── sendrecv/       # 发送接收功能
│   ├── sender.go   # 包发送器
│   ├── sniffer.go  # 包捕获器
│   └── socket.go   # 原始套接字
├── automaton/      # 自动化工具
│   ├── automaton.go # 状态机
│   └── session.go  # 会话管理
├── utils/          # 工具函数
│   ├── hexdump.go  # 十六进制转储
│   ├── analysis.go # 包分析
│   └── convert.go  # 类型转换
└── cmd/            # CLI命令
    ├── scapy.go    # 主命令
    └── subcmds/    # 子命令
```

## 核心组件设计

### 1. 包构造系统 (core/)

**Packet 基类设计：**
```go
type Packet interface {
    Build() ([]byte, error)        // 构建原始字节
    Dissect([]byte) error          // 解析原始字节
    GetLayer(layerType LayerType) Packet  // 获取指定层
    AddLayer(layer Packet)         // 添加协议层
    String() string                // 字符串表示
    HexDump() string               // 十六进制转储
}

type BasePacket struct {
    layers     []Packet            // 协议层栈
    payload    []byte              // 负载数据
    timestamp  time.Time           // 时间戳
}
```

**字段系统设计：**
```go
// 字段接口
type Field interface {
    Marshal() ([]byte, error)      // 序列化
    Unmarshal([]byte) error        // 反序列化
    Size() int                     // 字段大小
    Default() interface{}          // 默认值
}

// 具体字段类型
type ByteField struct{ Value byte }
type Uint16Field struct{ Value uint16 }
type IPField struct{ Value net.IP }
type MACField struct{ Value net.HardwareAddr }
```

### 2. 协议层系统 (layers/)

**协议层接口：**
```go
type Layer interface {
    Packet
    LayerType() LayerType          // 层类型标识
    NextLayerType() LayerType      // 下一层类型
    Checksum() (uint16, error)     // 计算校验和
}

// 层类型枚举
const (
    LayerEthernet LayerType = iota
    LayerIP
    LayerTCP
    LayerUDP
    LayerICMP
    // ... 更多协议层
)
```

### 3. 发送接收系统 (sendrecv/)

**发送器设计：**
```go
type Sender interface {
    Send(packet Packet) error      // 发送单个包
    SendLoop(packets []Packet) error // 发送多个包
    SetInterface(iface string) error // 设置网络接口
}

**捕获器设计：**
```go
type Sniffer interface {
    Start() error                  // 开始捕获
    Stop() error                   // 停止捕获
    Capture(count int) ([]Packet, error) // 捕获指定数量包
    SetFilter(filter string) error // 设置BPF过滤器
}
```

## 移植优先级

### 第一阶段：核心功能 (高优先级)
1. 包构造系统 (Packet, Field)
2. 基础协议层 (Ethernet, IP, TCP, UDP, ICMP)
3. 基本发送接收功能
4. CLI命令框架

### 第二阶段：扩展功能 (中优先级)
1. 更多协议层支持 (ARP, DNS, HTTP等)
2. 包分析工具
3. 自动化功能
4. 高级扫描技术

### 第三阶段：高级功能 (低优先级)
1. 完整协议栈支持
2. 性能优化
3. 高级分析工具
4. 图形界面集成

## 与现有代码的集成

当前已实现的Go Scapy功能将作为基础，逐步扩展为完整的Scapy移植版本。现有代码将重构为新的架构设计。