// +build linux

package tcpraw

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"sync"
	"syscall"
	"time"

	"github.com/coreos/go-iptables/iptables"
	"github.com/google/gopacket"
	"github.com/google/gopacket/afpacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/net/bpf"
)

var (
	errOpNotImplemented = errors.New("operation not implemented")
	expire              = 30 * time.Minute
)

type message struct {
	bts  []byte
	addr string
}

// tcp flow information for a connection pair
type tcpFlow struct {
	handle       *afpacket.TPacket // used in WriteTo to WritePacketData
	ready        chan struct{}     // mark whether the flow is ready to WriteTo
	seq          uint32
	ack          uint32
	linkLayer    gopacket.SerializableLayer // link layer header
	networkLayer gopacket.SerializableLayer // network layer header
	ts           time.Time                  // last packet incoming
}

// TCPConn defines a TCP-packet oriented connection
type TCPConn struct {
	die     chan struct{}
	dieOnce sync.Once

	// the original connection
	tcpconn  *net.TCPConn
	listener *net.TCPListener
	// connections accepted from listener
	osConns     map[string]net.Conn
	osConnsLock sync.Mutex

	// gopacket
	handles   []*afpacket.TPacket
	chMessage chan message // incoming packets channel

	// important TCP header information
	flowTable map[string]tcpFlow
	flowsLock sync.Mutex

	// iptables
	iptables *iptables.IPTables
	iprule   []string

	ip6tables *iptables.IPTables
	ip6rule   []string
}

// lockflow locks the flow table and apply function f on the entry
func (conn *TCPConn) lockflow(addr net.Addr, f func(e *tcpFlow)) {
	key := addr.String()
	conn.flowsLock.Lock()
	e, ok := conn.flowTable[key]
	if !ok { // entry first visit
		e.ready = make(chan struct{})
		e.ts = time.Now()
	}
	f(&e)
	conn.flowTable[key] = e
	conn.flowsLock.Unlock()
}

// clean expired conns for listener
func (conn *TCPConn) cleaner() {
	ticker := time.NewTicker(time.Minute)
	select {
	case <-conn.die:
		return
	case <-ticker.C:
		conn.flowsLock.Lock()
		for k, v := range conn.flowTable {
			if time.Now().Sub(v.ts) > expire {
				delete(conn.flowTable, k)
			}
		}
		conn.flowsLock.Unlock()
	}
}

// setTTL sets the Time-To-Live field on a given connection
func (conn *TCPConn) setTTL(x interface{}, ttl int) (err error) {
	var raw syscall.RawConn
	var addr *net.TCPAddr

	if l, ok := x.(*net.TCPListener); ok {
		raw, err = l.SyscallConn()
		if err != nil {
			return err
		}
		addr = l.Addr().(*net.TCPAddr)
	} else if c, ok := x.(*net.TCPConn); ok {
		raw, err = c.SyscallConn()
		if err != nil {
			return err
		}
		addr = c.LocalAddr().(*net.TCPAddr)
	}

	if addr.IP.To4() == nil {
		raw.Control(func(fd uintptr) {
			err = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_UNICAST_HOPS, ttl)
		})
	} else {
		raw.Control(func(fd uintptr) {
			err = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TTL, ttl)
		})
	}
	return
}

// captureFlow capture each packets inbound based on rules of BPF
func (conn *TCPConn) captureFlow(handle *afpacket.TPacket) {
	defer handle.Close()

	for {
		data, _, err := handle.ZeroCopyReadPacketData()
		if err != nil {
			return
		}
		packet := gopacket.NewPacket(data, layers.LinkTypeEthernet, gopacket.DecodeOptions{NoCopy: true, Lazy: true})
		transport := packet.TransportLayer().(*layers.TCP)
		if transport == nil { // retry on loopback link layer
			packet = gopacket.NewPacket(data, layers.LinkTypeLoop, gopacket.DecodeOptions{NoCopy: true, Lazy: true})
			transport = packet.TransportLayer().(*layers.TCP)
		}

		if transport != nil {
			// build transient address
			var addr net.TCPAddr
			addr.Port = int(transport.SrcPort)
			var toAddr net.TCPAddr
			toAddr.Port = int(transport.DstPort)

			if layer := packet.Layer(layers.LayerTypeIPv4); layer != nil {
				network := layer.(*layers.IPv4)
				addr.IP = network.SrcIP
				toAddr.IP = network.DstIP
			} else if layer := packet.Layer(layers.LayerTypeIPv6); layer != nil {
				network := layer.(*layers.IPv6)
				addr.IP = network.SrcIP
				toAddr.IP = network.DstIP
			}

			if conn.tcpconn != nil {
				laddr := conn.tcpconn.RemoteAddr().(*net.TCPAddr)
				if laddr.Port != addr.Port {
					continue
				}
				if bytes.Compare(laddr.IP, addr.IP) != 0 {
					continue
				}
			} else {
				laddr := conn.listener.Addr().(*net.TCPAddr)
				if laddr.Port != toAddr.Port {
					continue
				}
			}

			conn.lockflow(&addr, func(e *tcpFlow) {
				e.ts = time.Now()
				if transport.ACK {
					e.seq = transport.Ack
				}
				if transport.SYN { // for SYN packets, try initialize the flow entry once
					e.ack = transport.Seq + 1
					select {
					case <-e.ready:
					default:
						e.handle = handle

						// create link layer for WriteTo
						if layer := packet.Layer(layers.LayerTypeEthernet); layer != nil {
							ethLayer := layer.(*layers.Ethernet)
							e.linkLayer = &layers.Ethernet{
								EthernetType: ethLayer.EthernetType,
								SrcMAC:       ethLayer.DstMAC,
								DstMAC:       ethLayer.SrcMAC,
							}
						} else if layer := packet.Layer(layers.LayerTypeLoopback); layer != nil {
							loopLayer := layer.(*layers.Loopback)
							e.linkLayer = &layers.Loopback{Family: loopLayer.Family}
						}

						// create network layer for WriteTo
						if layer := packet.Layer(layers.LayerTypeIPv4); layer != nil {
							network := layer.(*layers.IPv4)
							e.networkLayer = &layers.IPv4{
								SrcIP:    network.DstIP,
								DstIP:    network.SrcIP,
								Protocol: network.Protocol,
								Version:  network.Version,
								Flags:    layers.IPv4DontFragment,
								TTL:      64,
							}
						} else if layer := packet.Layer(layers.LayerTypeIPv6); layer != nil {
							network := layer.(*layers.IPv6)
							e.networkLayer = &layers.IPv6{
								Version:    network.Version,
								NextHeader: network.NextHeader,
								SrcIP:      network.DstIP,
								DstIP:      network.SrcIP,
								HopLimit:   64,
							}
						}

						// this tcp flow is ready to operate based on flow information
						if e.linkLayer != nil && e.networkLayer != nil {
							close(e.ready)
						}
					}
				} else if transport.PSH {
					e.ack += uint32(len(transport.Payload))
				}
			})

			if transport.PSH {
				payload := make([]byte, len(transport.Payload))
				copy(payload, transport.Payload)
				select {
				case conn.chMessage <- message{payload, addr.String()}:
				case <-conn.die:
					return
				}
			}
		}
	}
}

// ReadFrom implements the PacketConn ReadFrom method.
func (conn *TCPConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	select {
	case <-conn.die:
		return 0, nil, io.EOF
	case packet := <-conn.chMessage:
		n = copy(p, packet.bts)
		addr, _ = net.ResolveTCPAddr("tcp", packet.addr)
		return n, addr, nil
	}
}

// WriteTo implements the PacketConn WriteTo method.
func (conn *TCPConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	return conn.writeToWithFlags(p, addr, false, true, true, false, false)
}

func (conn *TCPConn) writeToWithFlags(p []byte, addr net.Addr, SYN bool, PSH bool, ACK bool, FIN bool, RST bool) (n int, err error) {
	var ready chan struct{}
	conn.lockflow(addr, func(e *tcpFlow) { ready = e.ready })

	select {
	case <-conn.die:
		return 0, io.EOF
	case <-ready:
		tcpaddr, err := net.ResolveTCPAddr("tcp", addr.String())
		if err != nil {
			return 0, err
		}

		buf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		}

		// fetch flow
		var flow tcpFlow
		conn.lockflow(addr, func(e *tcpFlow) { flow = *e })

		var localAddr *net.TCPAddr
		if conn.tcpconn != nil {
			localAddr = conn.tcpconn.LocalAddr().(*net.TCPAddr)
		} else {
			localAddr = conn.listener.Addr().(*net.TCPAddr)
		}
		tcp := &layers.TCP{
			SrcPort: layers.TCPPort(localAddr.Port),
			DstPort: layers.TCPPort(tcpaddr.Port),
			Window:  12580,
			Ack:     flow.ack,
			Seq:     flow.seq,
			SYN:     SYN,
			PSH:     PSH,
			ACK:     ACK,
			FIN:     FIN,
			RST:     RST,
		}

		tcp.SetNetworkLayerForChecksum(flow.networkLayer.(gopacket.NetworkLayer))

		payload := gopacket.Payload(p)

		gopacket.SerializeLayers(buf, opts, flow.linkLayer, flow.networkLayer, tcp, payload)
		if err := flow.handle.WritePacketData(buf.Bytes()); err != nil {
			return 0, err
		}
		buf.Clear()

		conn.lockflow(addr, func(e *tcpFlow) { e.seq += uint32(len(p)) })
		return len(p), nil
	}
}

// Close closes the connection.
func (conn *TCPConn) Close() error {
	var err error
	conn.dieOnce.Do(func() {
		// close all established tcp connections
		if conn.tcpconn != nil {
			conn.setTTL(conn.tcpconn, 64)
			err = conn.tcpconn.Close()
		} else if conn.listener != nil {
			err = conn.listener.Close() // close listener
			conn.osConnsLock.Lock()
			for _, tcpconn := range conn.osConns { // close all accepted conns
				conn.setTTL(tcpconn, 64)
				tcpconn.Close()
			}
			conn.osConns = nil
			conn.osConnsLock.Unlock()
		}

		// delete iptable
		if conn.iptables != nil {
			conn.iptables.Delete("filter", "OUTPUT", conn.iprule...)
		}
		if conn.ip6tables != nil {
			conn.ip6tables.Delete("filter", "OUTPUT", conn.ip6rule...)
		}

	})
	return err
}

// LocalAddr returns the local network address.
func (conn *TCPConn) LocalAddr() net.Addr {
	if conn.tcpconn != nil {
		return conn.tcpconn.LocalAddr()
	} else if conn.listener != nil {
		return conn.listener.Addr()
	}
	return nil
}

// SetDeadline implements the Conn SetDeadline method.
func (conn *TCPConn) SetDeadline(t time.Time) error { return errOpNotImplemented }

// SetReadDeadline implements the Conn SetReadDeadline method.
func (conn *TCPConn) SetReadDeadline(t time.Time) error { return errOpNotImplemented }

// SetWriteDeadline implements the Conn SetWriteDeadline method.
func (conn *TCPConn) SetWriteDeadline(t time.Time) error { return errOpNotImplemented }

// Dial connects to the remote TCP port,
// and returns a single packet-oriented connection
func Dial(network, address string) (*TCPConn, error) {
	// remote address resolve
	raddr, err := net.ResolveTCPAddr(network, address)
	if err != nil {
		return nil, err
	}

	// create a dummy UDP socket, to get routing information
	dummy, err := net.Dial("udp", address)
	if err != nil {
		return nil, err
	}

	// get iface name from the dummy connection, eg. eth0, lo0
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var ifaceName string
	for _, iface := range ifaces {
		if addrs, err := iface.Addrs(); err == nil {
			for _, addr := range addrs {
				if ipaddr, ok := addr.(*net.IPNet); ok {
					if ipaddr.IP.Equal(dummy.LocalAddr().(*net.UDPAddr).IP) {
						ifaceName = iface.Name
					}
				}
			}
		}
	}
	if ifaceName == "" {
		return nil, errors.New("cannot find correct interface")
	}

	// afpacket init
	handle, err := afpacket.NewTPacket(
		afpacket.OptInterface(ifaceName),
		afpacket.SocketRaw,
		afpacket.TPacketVersion3)
	if err != nil {
		return nil, err
	}

	// TCP local address reuses the same address from UDP
	laddr, err := net.ResolveTCPAddr(network, dummy.LocalAddr().String())
	if err != nil {
		return nil, err
	}
	dummy.Close()

	// apply filter
	filter := []bpf.RawInstruction{
		{0x28, 0, 0, 0x0000000c},
		{0x15, 0, 6, 0x000086dd},
		{0x30, 0, 0, 0x00000014},
		{0x15, 2, 0, 0x00000084},
		{0x15, 1, 0, 0x00000006},
		{0x15, 0, 13, 0x00000011},
		{0x28, 0, 0, 0x00000038},
		{0x15, 10, 11, uint32(laddr.Port)},
		{0x15, 0, 10, 0x00000800},
		{0x30, 0, 0, 0x00000017},
		{0x15, 2, 0, 0x00000084},
		{0x15, 1, 0, 0x00000006},
		{0x15, 0, 6, 0x00000011},
		{0x28, 0, 0, 0x00000014},
		{0x45, 4, 0, 0x00001fff},
		{0xb1, 0, 0, 0x0000000e},
		{0x48, 0, 0, 0x00000010},
		{0x15, 0, 1, uint32(laddr.Port)},
		{0x6, 0, 0, 0x00040000},
		{0x6, 0, 0, 0x00000000}}

	handle.SetBPF(filter)

	// create an established tcp connection
	// will hack this tcp connection for packet transmission
	tcpconn, err := net.DialTCP(network, laddr, raddr)
	if err != nil {
		return nil, err
	}

	// fields
	conn := new(TCPConn)
	conn.die = make(chan struct{})
	conn.flowTable = make(map[string]tcpFlow)
	conn.handles = []*afpacket.TPacket{handle}
	conn.tcpconn = tcpconn
	conn.chMessage = make(chan message)
	go conn.captureFlow(handle)

	// iptables
	err = conn.setTTL(tcpconn, 1)
	if err != nil {
		return nil, err
	}

	if ipt, err := iptables.NewWithProtocol(iptables.ProtocolIPv4); err == nil {
		rule := []string{"-m", "ttl", "--ttl-eq", "1", "-p", "tcp", "-d", raddr.IP.String(), "--dport", fmt.Sprint(raddr.Port), "-j", "DROP"}
		if exists, err := ipt.Exists("filter", "OUTPUT", rule...); err == nil {
			if !exists {
				if err = ipt.Append("filter", "OUTPUT", rule...); err == nil {
					conn.iprule = rule
					conn.iptables = ipt
				}
			}
		}
	}
	if ipt, err := iptables.NewWithProtocol(iptables.ProtocolIPv6); err == nil {
		rule := []string{"-m", "hl", "--hl-eq", "1", "-p", "tcp", "-d", raddr.IP.String(), "--dport", fmt.Sprint(raddr.Port), "-j", "DROP"}
		if exists, err := ipt.Exists("filter", "OUTPUT", rule...); err == nil {
			if !exists {
				if err = ipt.Append("filter", "OUTPUT", rule...); err == nil {
					conn.ip6rule = rule
					conn.ip6tables = ipt
				}
			}
		}
	}

	// discards data flow on tcp conn
	go func() {
		io.Copy(ioutil.Discard, tcpconn)
		tcpconn.Close()
	}()

	return conn, nil
}

// Listen acts like net.ListenTCP,
// and returns a single packet-oriented connection
func Listen(network, address string) (*TCPConn, error) {
	laddr, err := net.ResolveTCPAddr(network, address)
	if err != nil {
		return nil, err
	}

	// get iface name from the dummy connection, eg. eth0, lo0
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var handles []*afpacket.TPacket
	if laddr.IP == nil || laddr.IP.IsUnspecified() { // if address is not specified, capture on all ifaces
		for _, iface := range ifaces {
			if addrs, err := iface.Addrs(); err == nil {
				// build dst host
				var hasIP bool
				var dsthost = "("
				for k, addr := range addrs {
					if ipaddr, ok := addr.(*net.IPNet); ok {
						dsthost += "dst host " + ipaddr.IP.String()
						hasIP = true
						if k != len(addrs)-1 {
							dsthost += " or "
						} else {
							dsthost += ")"
						}
					}
				}

				// try open on all nics
				if hasIP {
					if handle, err := afpacket.NewTPacket(
						afpacket.OptInterface(iface.Name),
						afpacket.SocketRaw,
						afpacket.TPacketVersion3); err == nil {
						handles = append(handles, handle)
						// apply filter
						filter := []bpf.RawInstruction{
							{0x28, 0, 0, 0x0000000c},
							{0x15, 0, 6, 0x000086dd},
							{0x30, 0, 0, 0x00000014},
							{0x15, 2, 0, 0x00000084},
							{0x15, 1, 0, 0x00000006},
							{0x15, 0, 13, 0x00000011},
							{0x28, 0, 0, 0x00000038},
							{0x15, 10, 11, uint32(laddr.Port)},
							{0x15, 0, 10, 0x00000800},
							{0x30, 0, 0, 0x00000017},
							{0x15, 2, 0, 0x00000084},
							{0x15, 1, 0, 0x00000006},
							{0x15, 0, 6, 0x00000011},
							{0x28, 0, 0, 0x00000014},
							{0x45, 4, 0, 0x00001fff},
							{0xb1, 0, 0, 0x0000000e},
							{0x48, 0, 0, 0x00000010},
							{0x15, 0, 1, uint32(laddr.Port)},
							{0x6, 0, 0, 0x00040000},
							{0x6, 0, 0, 0x00000000}}

						handle.SetBPF(filter)
					} else {
						return nil, err
					}
				}
			}
		}
	} else {
		var ifaceName string
		for _, iface := range ifaces {
			if addrs, err := iface.Addrs(); err == nil {
				for _, addr := range addrs {
					if ipaddr, ok := addr.(*net.IPNet); ok {
						if ipaddr.IP.Equal(laddr.IP) {
							ifaceName = iface.Name
						}
					}
				}
			}
		}
		if ifaceName == "" {
			return nil, errors.New("cannot find correct interface")
		}

		// afpacket init
		if handle, err := afpacket.NewTPacket(
			afpacket.OptInterface(ifaceName),
			afpacket.SocketRaw,
			afpacket.TPacketVersion3); err == nil {
			// apply filter
			filter := []bpf.RawInstruction{
				{0x28, 0, 0, 0x0000000c},
				{0x15, 0, 6, 0x000086dd},
				{0x30, 0, 0, 0x00000014},
				{0x15, 2, 0, 0x00000084},
				{0x15, 1, 0, 0x00000006},
				{0x15, 0, 13, 0x00000011},
				{0x28, 0, 0, 0x00000038},
				{0x15, 10, 11, uint32(laddr.Port)},
				{0x15, 0, 10, 0x00000800},
				{0x30, 0, 0, 0x00000017},
				{0x15, 2, 0, 0x00000084},
				{0x15, 1, 0, 0x00000006},
				{0x15, 0, 6, 0x00000011},
				{0x28, 0, 0, 0x00000014},
				{0x45, 4, 0, 0x00001fff},
				{0xb1, 0, 0, 0x0000000e},
				{0x48, 0, 0, 0x00000010},
				{0x15, 0, 1, uint32(laddr.Port)},
				{0x6, 0, 0, 0x00040000},
				{0x6, 0, 0, 0x00000000}}

			handle.SetBPF(filter)
			handles = []*afpacket.TPacket{handle}
		} else {
			return nil, err
		}
	}

	// start listening
	l, err := net.ListenTCP(network, laddr)
	if err != nil {
		return nil, err
	}

	// fields
	conn := new(TCPConn)
	conn.osConns = make(map[string]net.Conn)
	conn.handles = handles
	conn.flowTable = make(map[string]tcpFlow)
	conn.die = make(chan struct{})
	conn.chMessage = make(chan message)
	conn.listener = l

	// iptables
	if ipt, err := iptables.NewWithProtocol(iptables.ProtocolIPv4); err == nil {
		rule := []string{"-m", "ttl", "--ttl-eq", "1", "-p", "tcp", "--sport", fmt.Sprint(laddr.Port), "-j", "DROP"}
		if exists, err := ipt.Exists("filter", "OUTPUT", rule...); err == nil {
			if !exists {
				if err = ipt.Append("filter", "OUTPUT", rule...); err == nil {
					conn.iprule = rule
					conn.iptables = ipt
				}
			}
		}
	}
	if ipt, err := iptables.NewWithProtocol(iptables.ProtocolIPv6); err == nil {
		rule := []string{"-m", "hl", "--hl-eq", "1", "-p", "tcp", "--sport", fmt.Sprint(laddr.Port), "-j", "DROP"}
		if exists, err := ipt.Exists("filter", "OUTPUT", rule...); err == nil {
			if !exists {
				if err = ipt.Append("filter", "OUTPUT", rule...); err == nil {
					conn.ip6rule = rule
					conn.ip6tables = ipt
				}
			}
		}
	}

	for k := range handles {
		go conn.captureFlow(handles[k])
	}

	// discard everything in original connection
	go func() {
		for {
			tcpconn, err := l.Accept()
			if err != nil {
				return
			}

			conn.setTTL(tcpconn, 1)
			conn.osConnsLock.Lock()
			conn.osConns[tcpconn.LocalAddr().String()] = tcpconn
			conn.osConnsLock.Unlock()
			go func() {
				io.Copy(ioutil.Discard, tcpconn)
				tcpconn.Close()
			}()
		}
	}()

	return conn, nil
}