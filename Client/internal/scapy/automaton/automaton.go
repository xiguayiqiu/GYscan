package automaton

import (
	"fmt"
	"net"
	"time"

	"GYscan/internal/scapy/core"
	"GYscan/internal/scapy/layers"
	"GYscan/internal/scapy/sendrecv"
)

// State 状态机状态
type State string

// Event 状态机事件
type Event string

// Transition 状态转移
type Transition struct {
	FromState State                  // 源状态
	Event     Event                  // 触发事件
	ToState   State                  // 目标状态
	Action    func(*Automaton) error // 转移动作
	Condition func(*Automaton) bool  // 转移条件
}

// Automaton 状态机
type Automaton struct {
	Name         string                 // 状态机名称
	CurrentState State                  // 当前状态
	States       map[State]bool         // 所有状态
	Transitions  []Transition           // 状态转移
	Data         map[string]interface{} // 状态机数据
	Sender       *sendrecv.Sender       // 包发送器
	Sniffer      *sendrecv.Sniffer      // 包捕获器
	Timeout      time.Duration          // 超时时间
	StopChan     chan struct{}          // 停止通道
	ErrorChan    chan error             // 错误通道
}

// NewAutomaton 创建新的状态机
func NewAutomaton(name string, sender *sendrecv.Sender, sniffer *sendrecv.Sniffer) *Automaton {
	return &Automaton{
		Name:         name,
		CurrentState: "",
		States:       make(map[State]bool),
		Transitions:  make([]Transition, 0),
		Data:         make(map[string]interface{}),
		Sender:       sender,
		Sniffer:      sniffer,
		Timeout:      30 * time.Second,
		StopChan:     make(chan struct{}),
		ErrorChan:    make(chan error, 1),
	}
}

// AddState 添加状态
func (a *Automaton) AddState(state State) {
	a.States[state] = true
}

// AddTransition 添加状态转移
func (a *Automaton) AddTransition(transition Transition) {
	a.Transitions = append(a.Transitions, transition)
}

// SetInitialState 设置初始状态
func (a *Automaton) SetInitialState(state State) error {
	if _, exists := a.States[state]; !exists {
		return fmt.Errorf("state %s not defined", state)
	}
	a.CurrentState = state
	return nil
}

// Start 启动状态机
func (a *Automaton) Start() error {
	if a.CurrentState == "" {
		return fmt.Errorf("initial state not set")
	}

	go a.run()
	return nil
}

// Stop 停止状态机
func (a *Automaton) Stop() {
	close(a.StopChan)
}

// Wait 等待状态机完成
func (a *Automaton) Wait() error {
	select {
	case err := <-a.ErrorChan:
		return err
	case <-a.StopChan:
		return nil
	}
}

// run 状态机运行循环
func (a *Automaton) run() {
	defer close(a.ErrorChan)

	for {
		select {
		case <-a.StopChan:
			return
		default:
			// 检查是否有可用的转移
			transition, found := a.findTransition()
			if !found {
				// 没有可用转移，等待或超时
				timer := time.NewTimer(a.Timeout)
				select {
				case <-timer.C:
					a.ErrorChan <- fmt.Errorf("timeout in state %s", a.CurrentState)
					return
				case <-a.StopChan:
					timer.Stop()
					return
				}
			}

			// 执行转移
			if err := a.executeTransition(transition); err != nil {
				a.ErrorChan <- err
				return
			}
		}
	}
}

// findTransition 查找可用的状态转移
func (a *Automaton) findTransition() (Transition, bool) {
	for _, transition := range a.Transitions {
		if transition.FromState == a.CurrentState {
			// 检查条件
			if transition.Condition != nil && !transition.Condition(a) {
				continue
			}
			return transition, true
		}
	}
	return Transition{}, false
}

// executeTransition 执行状态转移
func (a *Automaton) executeTransition(transition Transition) error {
	// 执行动作
	if transition.Action != nil {
		if err := transition.Action(a); err != nil {
			return fmt.Errorf("action failed: %v", err)
		}
	}

	// 更新状态
	a.CurrentState = transition.ToState
	return nil
}

// SetData 设置状态机数据
func (a *Automaton) SetData(key string, value interface{}) {
	a.Data[key] = value
}

// GetData 获取状态机数据
func (a *Automaton) GetData(key string) interface{} {
	return a.Data[key]
}

// CommonStates 常用状态
const (
	StateInit    State = "init"
	StateWait    State = "wait"
	StateSend    State = "send"
	StateReceive State = "receive"
	StateSuccess State = "success"
	StateFailure State = "failure"
	StateTimeout State = "timeout"
)

// CommonEvents 常用事件
const (
	EventStart   Event = "start"
	EventSend    Event = "send"
	EventReceive Event = "receive"
	EventTimeout Event = "timeout"
	EventSuccess Event = "success"
	EventFailure Event = "failure"
)

// TCPHandshakeAutomaton TCP握手状态机
type TCPHandshakeAutomaton struct {
	*Automaton
	TargetIP   string
	TargetPort uint16
	LocalPort  uint16
	SeqNumber  uint32
	AckNumber  uint32
}

// NewTCPHandshakeAutomaton 创建TCP握手状态机
func NewTCPHandshakeAutomaton(targetIP string, targetPort uint16, sender *sendrecv.Sender, sniffer *sendrecv.Sniffer) *TCPHandshakeAutomaton {
	auto := NewAutomaton("tcp_handshake", sender, sniffer)
	handshake := &TCPHandshakeAutomaton{
		Automaton:  auto,
		TargetIP:   targetIP,
		TargetPort: targetPort,
		LocalPort:  54321, // 随机本地端口
		SeqNumber:  1000,  // 初始序列号
	}

	handshake.setupStatesAndTransitions()
	return handshake
}

// setupStatesAndTransitions 设置TCP握手的状态和转移
func (t *TCPHandshakeAutomaton) setupStatesAndTransitions() {
	// 添加状态
	t.AddState(StateInit)
	t.AddState(StateSend)
	t.AddState(StateWait)
	t.AddState(StateSuccess)
	t.AddState(StateFailure)
	t.AddState(StateTimeout)

	// 设置初始状态
	t.SetInitialState(StateInit)

	// 添加转移
	t.AddTransition(Transition{
		FromState: StateInit,
		Event:     EventStart,
		ToState:   StateSend,
		Action:    t.sendSYNPacket,
	})

	t.AddTransition(Transition{
		FromState: StateSend,
		Event:     EventSend,
		ToState:   StateWait,
		Action:    t.startSniffing,
	})

	t.AddTransition(Transition{
		FromState: StateWait,
		Event:     EventReceive,
		ToState:   StateSuccess,
		Condition: t.isSYNACKPacket,
		Action:    t.processSYNACK,
	})

	t.AddTransition(Transition{
		FromState: StateWait,
		Event:     EventTimeout,
		ToState:   StateFailure,
	})

	t.AddTransition(Transition{
		FromState: StateWait,
		Event:     EventReceive,
		ToState:   StateFailure,
		Condition: t.isRSTPacket,
	})
}

// sendSYNPacket 发送SYN包
func (t *TCPHandshakeAutomaton) sendSYNPacket(a *Automaton) error {
	synPacket := layers.CreateSYNPacket(t.LocalPort, t.TargetPort, t.SeqNumber)

	localIP := t.Sender.GetLocalAddress()
	targetIP := net.ParseIP(t.TargetIP)

	if err := t.Sender.SendTCPPacket(synPacket, localIP, targetIP); err != nil {
		return fmt.Errorf("failed to send SYN packet: %v", err)
	}

	t.SetData("syn_sent", true)
	return nil
}

// startSniffing 开始捕获
func (t *TCPHandshakeAutomaton) startSniffing(a *Automaton) error {
	// 设置过滤器只捕获目标端口的TCP包
	filter := fmt.Sprintf("tcp and host %s and port %d", t.TargetIP, t.TargetPort)
	t.Sniffer.SetFilter(filter)

	// 启动异步捕获
	asyncSniffer, err := sendrecv.NewAsyncSniffer(
		t.Sniffer.GetInterface().Name,
		sendrecv.DefaultSnifferConfig,
		t.handlePacket,
	)
	if err != nil {
		return err
	}

	return asyncSniffer.Start()
}

// handlePacket 处理捕获的包
func (t *TCPHandshakeAutomaton) handlePacket(packet *core.PacketInfo) error {
	// 检查是否是SYN-ACK包
	for _, layer := range packet.Layers {
		if layer.Type == "tcp" {
			flags, ok := layer.Fields["flags"].(string)
			if ok && flags == "SA" { // SYN-ACK标志
				t.Automaton.ErrorChan <- nil // 触发状态转移
				return nil
			}

			if ok && flags == "R" { // RST标志
				t.Automaton.ErrorChan <- fmt.Errorf("received RST packet")
				return nil
			}
		}
	}

	return nil
}

// isSYNACKPacket 检查是否是SYN-ACK包
func (t *TCPHandshakeAutomaton) isSYNACKPacket(a *Automaton) bool {
	// 在实际实现中，这里会检查捕获的包
	return true
}

// isRSTPacket 检查是否是RST包
func (t *TCPHandshakeAutomaton) isRSTPacket(a *Automaton) bool {
	// 在实际实现中，这里会检查捕获的包
	return false
}

// processSYNACK 处理SYN-ACK包
func (t *TCPHandshakeAutomaton) processSYNACK(a *Automaton) error {
	// 发送ACK包完成三次握手
	ackPacket := layers.CreateACKPacket(t.LocalPort, t.TargetPort, t.SeqNumber+1, t.AckNumber+1)

	localIP := t.Sender.GetLocalAddress()
	targetIP := net.ParseIP(t.TargetIP)

	if err := t.Sender.SendTCPPacket(ackPacket, localIP, targetIP); err != nil {
		return fmt.Errorf("failed to send ACK packet: %v", err)
	}

	t.SetData("handshake_complete", true)
	return nil
}

// PortScanAutomaton 端口扫描状态机
type PortScanAutomaton struct {
	*Automaton
	TargetIP    string
	Ports       []uint16
	CurrentPort int
	Results     map[uint16]string
}

// NewPortScanAutomaton 创建端口扫描状态机
func NewPortScanAutomaton(targetIP string, ports []uint16, sender *sendrecv.Sender, sniffer *sendrecv.Sniffer) *PortScanAutomaton {
	auto := NewAutomaton("port_scan", sender, sniffer)
	scan := &PortScanAutomaton{
		Automaton:   auto,
		TargetIP:    targetIP,
		Ports:       ports,
		CurrentPort: 0,
		Results:     make(map[uint16]string),
	}

	scan.setupStatesAndTransitions()
	return scan
}

// setupStatesAndTransitions 设置端口扫描的状态和转移
func (p *PortScanAutomaton) setupStatesAndTransitions() {
	// 添加状态
	p.AddState(StateInit)
	p.AddState("scan_port")
	p.AddState("wait_response")
	p.AddState("next_port")
	p.AddState(StateSuccess)
	p.AddState(StateFailure)

	// 设置初始状态
	p.SetInitialState(StateInit)

	// 添加转移
	p.AddTransition(Transition{
		FromState: StateInit,
		Event:     EventStart,
		ToState:   "scan_port",
		Action:    p.scanCurrentPort,
	})

	p.AddTransition(Transition{
		FromState: "scan_port",
		Event:     EventSend,
		ToState:   "wait_response",
		Action:    p.waitForResponse,
	})

	p.AddTransition(Transition{
		FromState: "wait_response",
		Event:     EventReceive,
		ToState:   "next_port",
		Condition: p.hasMorePorts,
		Action:    p.recordResult,
	})

	p.AddTransition(Transition{
		FromState: "wait_response",
		Event:     EventTimeout,
		ToState:   "next_port",
		Condition: p.hasMorePorts,
		Action:    p.recordTimeout,
	})

	p.AddTransition(Transition{
		FromState: "next_port",
		Event:     EventSuccess,
		ToState:   "scan_port",
		Action:    p.scanCurrentPort,
	})

	p.AddTransition(Transition{
		FromState: "next_port",
		Event:     EventFailure,
		ToState:   StateSuccess,
		Condition: p.noMorePorts,
	})
}

// scanCurrentPort 扫描当前端口
func (p *PortScanAutomaton) scanCurrentPort(a *Automaton) error {
	if p.CurrentPort >= len(p.Ports) {
		return fmt.Errorf("no more ports to scan")
	}

	port := p.Ports[p.CurrentPort]
	synPacket := layers.CreateSYNPacket(54321, port, 1000)

	localIP := p.Sender.GetLocalAddress()
	targetIP := net.ParseIP(p.TargetIP)

	if err := p.Sender.SendTCPPacket(synPacket, localIP, targetIP); err != nil {
		return fmt.Errorf("failed to send SYN packet to port %d: %v", port, err)
	}

	p.SetData("current_port", port)
	return nil
}

// waitForResponse 等待响应
func (p *PortScanAutomaton) waitForResponse(a *Automaton) error {
	// 设置超时定时器
	timer := time.NewTimer(3 * time.Second)
	defer timer.Stop()

	select {
	case <-timer.C:
		// 超时，端口可能关闭或无响应
		p.Results[p.Ports[p.CurrentPort]] = "closed"
	case <-p.StopChan:
		return nil
	}

	return nil
}

// recordResult 记录结果
func (p *PortScanAutomaton) recordResult(a *Automaton) error {
	port := p.Ports[p.CurrentPort]
	p.Results[port] = "open"
	p.CurrentPort++
	return nil
}

// recordTimeout 记录超时结果
func (p *PortScanAutomaton) recordTimeout(a *Automaton) error {
	port := p.Ports[p.CurrentPort]
	p.Results[port] = "filtered"
	p.CurrentPort++
	return nil
}

// hasMorePorts 检查是否还有更多端口
func (p *PortScanAutomaton) hasMorePorts(a *Automaton) bool {
	return p.CurrentPort < len(p.Ports)
}

// noMorePorts 检查是否没有更多端口
func (p *PortScanAutomaton) noMorePorts(a *Automaton) bool {
	return p.CurrentPort >= len(p.Ports)
}

// GetResults 获取扫描结果
func (p *PortScanAutomaton) GetResults() map[uint16]string {
	return p.Results
}
