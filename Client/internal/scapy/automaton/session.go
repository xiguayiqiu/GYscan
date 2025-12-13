package automaton

import (
	"fmt"
	"net"
	"sync"
	"time"

	"GYscan/internal/scapy/core"
	"GYscan/internal/scapy/layers"
	"GYscan/internal/scapy/sendrecv"
)

// Session 会话管理
type Session struct {
	ID           string                 // 会话ID
	Protocol     string                 // 协议类型
	LocalIP      string                 // 本地IP地址
	RemoteIP     string                 // 远程IP地址
	LocalPort    uint16                 // 本地端口
	RemotePort   uint16                 // 远程端口
	State        string                 // 当前状态
	StartTime    time.Time              // 开始时间
	LastActivity time.Time              // 最后活动时间
	Data         map[string]interface{} // 会话数据
	PacketQueue  chan *core.PacketInfo  // 包队列
	StopChan     chan struct{}          // 停止通道
	Mutex        sync.RWMutex           // 读写锁
}

// SessionManager 会话管理器
type SessionManager struct {
	sessions map[string]*Session // 所有会话
	mutex    sync.RWMutex        // 读写锁
	sender   *sendrecv.Sender    // 包发送器
	sniffer  *sendrecv.Sniffer   // 包捕获器
}

// NewSessionManager 创建新的会话管理器
func NewSessionManager(sender *sendrecv.Sender, sniffer *sendrecv.Sniffer) *SessionManager {
	return &SessionManager{
		sessions: make(map[string]*Session),
		sender:   sender,
		sniffer:  sniffer,
	}
}

// NewSession 创建新会话
func (sm *SessionManager) NewSession(protocol, localIP, remoteIP string, localPort, remotePort uint16) (*Session, error) {
	sessionID := generateSessionID(protocol, localIP, remoteIP, localPort, remotePort)

	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	if _, exists := sm.sessions[sessionID]; exists {
		return nil, fmt.Errorf("session already exists: %s", sessionID)
	}

	session := &Session{
		ID:           sessionID,
		Protocol:     protocol,
		LocalIP:      localIP,
		RemoteIP:     remoteIP,
		LocalPort:    localPort,
		RemotePort:   remotePort,
		State:        "init",
		StartTime:    time.Now(),
		LastActivity: time.Now(),
		Data:         make(map[string]interface{}),
		PacketQueue:  make(chan *core.PacketInfo, 100),
		StopChan:     make(chan struct{}),
	}

	sm.sessions[sessionID] = session
	return session, nil
}

// GetSession 获取会话
func (sm *SessionManager) GetSession(sessionID string) (*Session, bool) {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	session, exists := sm.sessions[sessionID]
	return session, exists
}

// RemoveSession 移除会话
func (sm *SessionManager) RemoveSession(sessionID string) error {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	session, exists := sm.sessions[sessionID]
	if !exists {
		return fmt.Errorf("session not found: %s", sessionID)
	}

	close(session.StopChan)
	close(session.PacketQueue)
	delete(sm.sessions, sessionID)

	return nil
}

// ListSessions 列出所有会话
func (sm *SessionManager) ListSessions() []*Session {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	sessions := make([]*Session, 0, len(sm.sessions))
	for _, session := range sm.sessions {
		sessions = append(sessions, session)
	}

	return sessions
}

// StartSession 启动会话
func (s *Session) Start() error {
	s.Mutex.Lock()
	s.State = "active"
	s.Mutex.Unlock()

	// 启动包处理协程
	go s.packetHandler()

	return nil
}

// StopSession 停止会话
func (s *Session) Stop() error {
	s.Mutex.Lock()
	defer s.Mutex.Unlock()

	if s.State == "closed" {
		return fmt.Errorf("session already closed")
	}

	s.State = "closed"
	close(s.StopChan)

	return nil
}

// SendPacket 发送数据包
func (s *Session) SendPacket(packet core.Packet) error {
	s.Mutex.Lock()
	defer s.Mutex.Unlock()

	if s.State != "active" {
		return fmt.Errorf("session is not active")
	}

	// 更新最后活动时间
	s.LastActivity = time.Now()

	// 这里需要根据协议类型发送包
	// 简化实现，实际需要调用发送器
	return nil
}

// ReceivePacket 接收数据包
func (s *Session) ReceivePacket(timeout time.Duration) (*core.PacketInfo, error) {
	select {
	case packet := <-s.PacketQueue:
		s.Mutex.Lock()
		s.LastActivity = time.Now()
		s.Mutex.Unlock()
		return packet, nil
	case <-time.After(timeout):
		return nil, fmt.Errorf("receive timeout")
	case <-s.StopChan:
		return nil, fmt.Errorf("session closed")
	}
}

// packetHandler 包处理协程
func (s *Session) packetHandler() {
	for {
		select {
		case <-s.StopChan:
			return
		default:
			// 这里应该从捕获器接收包并放入队列
			// 简化实现
			time.Sleep(100 * time.Millisecond)
		}
	}
}

// SetData 设置会话数据
func (s *Session) SetData(key string, value interface{}) {
	s.Mutex.Lock()
	defer s.Mutex.Unlock()
	s.Data[key] = value
}

// GetData 获取会话数据
func (s *Session) GetData(key string) interface{} {
	s.Mutex.RLock()
	defer s.Mutex.RUnlock()
	return s.Data[key]
}

// GetState 获取会话状态
func (s *Session) GetState() string {
	s.Mutex.RLock()
	defer s.Mutex.RUnlock()
	return s.State
}

// GetDuration 获取会话持续时间
func (s *Session) GetDuration() time.Duration {
	return time.Since(s.StartTime)
}

// GetIdleTime 获取会话空闲时间
func (s *Session) GetIdleTime() time.Duration {
	s.Mutex.RLock()
	defer s.Mutex.RUnlock()
	return time.Since(s.LastActivity)
}

// TCPSession TCP会话
type TCPSession struct {
	*Session
	SeqNumber uint32 // 本地序列号
	AckNumber uint32 // 确认号
	Window    uint16 // 窗口大小
}

// NewTCPSession 创建TCP会话
func (sm *SessionManager) NewTCPSession(localIP, remoteIP string, localPort, remotePort uint16) (*TCPSession, error) {
	session, err := sm.NewSession("tcp", localIP, remoteIP, localPort, remotePort)
	if err != nil {
		return nil, err
	}

	tcpSession := &TCPSession{
		Session:   session,
		SeqNumber: 1000, // 初始序列号
		AckNumber: 0,
		Window:    8192,
	}

	return tcpSession, nil
}

// Handshake TCP握手
func (ts *TCPSession) Handshake() error {
	// 发送SYN包
	synPacket := layers.CreateSYNPacket(ts.LocalPort, ts.RemotePort, ts.SeqNumber)

	localIP := net.ParseIP(ts.LocalIP)
	remoteIP := net.ParseIP(ts.RemoteIP)

	// 这里需要调用发送器发送包
	// 简化实现
	_ = synPacket
	_ = localIP
	_ = remoteIP

	// 等待SYN-ACK响应
	timeout := 5 * time.Second
	_, err := ts.ReceivePacket(timeout)
	if err != nil {
		return fmt.Errorf("handshake failed: %v", err)
	}

	// 发送ACK包
	ts.SeqNumber++
	ts.AckNumber++

	ackPacket := layers.CreateACKPacket(ts.LocalPort, ts.RemotePort, ts.SeqNumber, ts.AckNumber)

	// 发送ACK包
	// 简化实现
	_ = ackPacket

	ts.SetState("established")
	return nil
}

// SendData 发送数据
func (ts *TCPSession) SendData(data []byte) error {
	if ts.GetState() != "established" {
		return fmt.Errorf("session not established")
	}

	// 创建数据包
	tcpPacket := layers.NewTCPPacket(ts.LocalPort, ts.RemotePort)
	tcpPacket.SetSequenceNumber(ts.SeqNumber)
	tcpPacket.SetAckNumber(ts.AckNumber)
	tcpPacket.SetFlag(layers.TCPFlagPSH | layers.TCPFlagACK)
	tcpPacket.SetPayload(data)

	// 发送包
	err := ts.SendPacket(tcpPacket)
	if err != nil {
		return err
	}

	// 更新序列号
	ts.SeqNumber += uint32(len(data))

	return nil
}

// ReceiveData 接收数据
func (ts *TCPSession) ReceiveData(timeout time.Duration) ([]byte, error) {
	packet, err := ts.ReceivePacket(timeout)
	if err != nil {
		return nil, err
	}

	// 解析TCP包获取数据
	// 简化实现
	for _, layer := range packet.Layers {
		if layer.Type == "tcp" {
			if payload, ok := layer.Data.([]byte); ok {
				return payload, nil
			}
		}
	}

	return nil, fmt.Errorf("no data received")
}

// Close 关闭TCP会话
func (ts *TCPSession) Close() error {
	if ts.GetState() == "closed" {
		return nil
	}

	// 发送FIN包
	finPacket := layers.CreateFINPacket(ts.LocalPort, ts.RemotePort, ts.SeqNumber, ts.AckNumber)
	err := ts.SendPacket(finPacket)
	if err != nil {
		return err
	}

	// 等待ACK
	_, err = ts.ReceivePacket(5 * time.Second)
	if err != nil {
		// 超时，强制关闭
	}

	ts.SetState("closed")
	return ts.Stop()
}

// SetState 设置会话状态
func (ts *TCPSession) SetState(state string) {
	ts.Mutex.Lock()
	defer ts.Mutex.Unlock()
	ts.State = state
}

// UDPSession UDP会话
type UDPSession struct {
	*Session
}

// NewUDPSession 创建UDP会话
func (sm *SessionManager) NewUDPSession(localIP, remoteIP string, localPort, remotePort uint16) (*UDPSession, error) {
	session, err := sm.NewSession("udp", localIP, remoteIP, localPort, remotePort)
	if err != nil {
		return nil, err
	}

	udpSession := &UDPSession{
		Session: session,
	}

	return udpSession, nil
}

// SendData 发送UDP数据
func (us *UDPSession) SendData(data []byte) error {
	udpPacket := layers.NewUDPPacket(us.LocalPort, us.RemotePort)
	udpPacket.SetPayload(data)

	return us.SendPacket(udpPacket)
}

// ReceiveData 接收UDP数据
func (us *UDPSession) ReceiveData(timeout time.Duration) ([]byte, error) {
	packet, err := us.ReceivePacket(timeout)
	if err != nil {
		return nil, err
	}

	// 解析UDP包获取数据
	for _, layer := range packet.Layers {
		if layer.Type == "udp" {
			if payload, ok := layer.Data.([]byte); ok {
				return payload, nil
			}
		}
	}

	return nil, fmt.Errorf("no data received")
}

// generateSessionID 生成会话ID
func generateSessionID(protocol, localIP, remoteIP string, localPort, remotePort uint16) string {
	return fmt.Sprintf("%s:%s:%d-%s:%d", protocol, localIP, localPort, remoteIP, remotePort)
}

// SessionStats 会话统计
type SessionStats struct {
	TotalSessions      int       // 总会话数
	ActiveSessions     int       // 活跃会话数
	TCPsessions        int       // TCP会话数
	UDPsessions        int       // UDP会话数
	TotalBytesSent     int64     // 总发送字节数
	TotalBytesReceived int64     // 总接收字节数
	StartTime          time.Time // 开始时间
}

// GetStats 获取会话管理器统计
func (sm *SessionManager) GetStats() SessionStats {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	stats := SessionStats{
		StartTime: time.Now(),
	}

	for _, session := range sm.sessions {
		stats.TotalSessions++

		if session.State == "active" {
			stats.ActiveSessions++
		}

		switch session.Protocol {
		case "tcp":
			stats.TCPsessions++
		case "udp":
			stats.UDPsessions++
		}
	}

	return stats
}

// CleanupInactiveSessions 清理非活跃会话
func (sm *SessionManager) CleanupInactiveSessions(maxIdleTime time.Duration) int {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	cleaned := 0
	now := time.Now()

	for sessionID, session := range sm.sessions {
		if now.Sub(session.LastActivity) > maxIdleTime {
			close(session.StopChan)
			close(session.PacketQueue)
			delete(sm.sessions, sessionID)
			cleaned++
		}
	}

	return cleaned
}

// SessionFactory 会话工厂
type SessionFactory struct {
	sessionManager *SessionManager
}

// NewSessionFactory 创建会话工厂
func NewSessionFactory(sender *sendrecv.Sender, sniffer *sendrecv.Sniffer) *SessionFactory {
	return &SessionFactory{
		sessionManager: NewSessionManager(sender, sniffer),
	}
}

// CreateTCPSession 创建TCP会话
func (sf *SessionFactory) CreateTCPSession(localIP, remoteIP string, localPort, remotePort uint16) (*TCPSession, error) {
	return sf.sessionManager.NewTCPSession(localIP, remoteIP, localPort, remotePort)
}

// CreateUDPSession 创建UDP会话
func (sf *SessionFactory) CreateUDPSession(localIP, remoteIP string, localPort, remotePort uint16) (*UDPSession, error) {
	return sf.sessionManager.NewUDPSession(localIP, remoteIP, localPort, remotePort)
}

// GetSessionManager 获取会话管理器
func (sf *SessionFactory) GetSessionManager() *SessionManager {
	return sf.sessionManager
}
