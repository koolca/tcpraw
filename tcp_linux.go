// The MIT License (MIT)
//
// Copyright (c) 2019 xtaci
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

//go:build linux

package tcpraw

import (
	"container/list"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
    "os"
    "os/signal"

	"github.com/coreos/go-iptables/iptables"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var (
	errOpNotImplemented = errors.New("operation not implemented") // Error for unimplemented operations
	errTimeout          = errors.New("timeout")                   // Error for operation timeout
	expire              = time.Minute                             // Duration to define expiration time for flows
)

var (
	connList   list.List
	connListMu sync.Mutex
)

// a message from NIC
type message struct {
	bts  []byte
	addr net.Addr
}

// a tcp flow information of a connection pair
type tcpFlow struct {
	conn         *net.TCPConn               // the related system TCP connection of this flow
	handle       *net.IPConn                // the handle to send packets
	seq          uint32                     // TCP sequence number
	ack          uint32                     // TCP acknowledge number
	tsEcr        uint32                     // TCP timestamp echo reply
	networkLayer gopacket.SerializableLayer // network layer header for tx
	ts           time.Time                  // last packet incoming time
	buf          gopacket.SerializeBuffer   // a buffer for write
	tcpHeader    layers.TCP
}

// TCPConn
type TCPConn struct {
	// a wrapper for tcpconn for gc purpose
	*tcpConn
}

// tcpConn defines a TCP-packet oriented connection
type tcpConn struct {
	elem    *list.Element // elem in the list
	die     chan struct{}
	dieOnce sync.Once

	// the main golang sockets
	tcpconn  *net.TCPConn     // from net.Dial
	listener *net.TCPListener // from net.Listen

	// handles
	handles []*net.IPConn

	// packets captured from all related NICs will be delivered to this channel
	chMessage chan message

	// all TCP flows
	flowTable map[string]*tcpFlow
	flowsLock sync.Mutex

	// iptables
    iptables  *iptables.IPTables // Handle for IPv4 iptables rules
    iprules   [][]string         // Changed: Support multiple IPv4 rules (TTL + RST)
    ip6tables *iptables.IPTables // Handle for IPv6 iptables rules
    ip6rules  [][]string         // Changed: Support multiple IPv6 rules

	// deadlines
	readDeadline  atomic.Value // Atomic value for read deadline
	writeDeadline atomic.Value // Atomic value for write deadline

	// serialization
	opts gopacket.SerializeOptions

	// fingerprints
	tcpFingerPrint fingerPrint
}

// lockflow locks the flow table and apply function `f` to the entry, and create one if not exist
func (conn *tcpConn) lockflow(addr net.Addr, f func(e *tcpFlow)) {
	key := addr.String()  // Use the string representation of the address as the key
	conn.flowsLock.Lock() // Lock the flowTable for safe access
	e := conn.flowTable[key]
	if e == nil { // entry first visit
		e = new(tcpFlow)                      // Create a new flow if it doesn't exist
		e.ts = time.Now()                     // Set the timestamp to the current time
		e.buf = gopacket.NewSerializeBuffer() // Initialize the serialization buffer
	}
	f(e)                    // Apply the function to the flow entry
	conn.flowTable[key] = e // Store the modified flow entry back into the table
	conn.flowsLock.Unlock() // Unlock the flowTable
}

// clean expired flows
func (conn *tcpConn) cleaner() {
	ticker := time.NewTicker(5 * time.Second) // Check every 5 seconds
	defer ticker.Stop()

	for {
		select {
		case <-conn.die: // Exit if the connection is closed
			return
		case <-ticker.C: // On each tick, clean up expired flows
			conn.flowsLock.Lock()
			now := time.Now()
			for k, v := range conn.flowTable {
				ttl := expire
				if v.conn == nil {
					ttl = 5 * time.Second // Short expire for orphans
				}

				if now.Sub(v.ts) > ttl { // Check if the flow has expired
					if v.conn != nil {
						setTTL(v.conn, 64) // Set TTL before closing the connection
						v.conn.Close()
					}
					delete(conn.flowTable, k) // Remove the flow from the table
				}
			}
			conn.flowsLock.Unlock()
		}
	}
}

// captureFlow capture every inbound packets based on rules of BPF
func (conn *tcpConn) captureFlow(handle *net.IPConn, port int) {
	buf := make([]byte, 2048)
	opt := gopacket.DecodeOptions{NoCopy: true, Lazy: true}
	for {
		n, addr, err := handle.ReadFromIP(buf)
		if err != nil {
			return
		}

		// try decoding TCP frame from buf[:n]
		packet := gopacket.NewPacket(buf[:n], layers.LayerTypeTCP, opt)
		transport := packet.TransportLayer()
		tcp, ok := transport.(*layers.TCP)
		if !ok {
			continue
		}

		// port filtering (Double check in userspace, though BPF should have filtered it)
		if int(tcp.DstPort) != port {
			continue
		}

		// address building
		var src net.TCPAddr
		src.IP = addr.IP
		src.Port = int(tcp.SrcPort)

		var orphan bool
		// flow maintaince
		conn.lockflow(&src, func(e *tcpFlow) {
			if e.conn == nil { // make sure it's related to net.TCPConn
				orphan = true // mark as orphan if it's not related net.TCPConn
			}

			// to keep track of TCP header related to this source
			e.ts = time.Now()
			if tcp.ACK {
				e.seq = tcp.Ack
			}

			// Parse TCP options to get Timestamp
			for _, opt := range tcp.Options {
				if opt.OptionType == layers.TCPOptionKindTimestamps && len(opt.OptionData) == 10 {
					e.tsEcr = binary.BigEndian.Uint32(opt.OptionData[:4])
					break
				}
			}

			// Update ACK
			nextSeq := tcp.Seq + uint32(len(tcp.Payload))
			if tcp.SYN {
				nextSeq++
			}
			if tcp.FIN {
				nextSeq++
			}

			// If we have payload or flags that consume sequence space, update ack
			if nextSeq != tcp.Seq {
				if e.ack == 0 || e.ack == tcp.Seq {
					e.ack = nextSeq
				}
			}

			e.handle = handle
		})

		// push data if it's not orphan
		if !orphan && tcp.PSH {
			payload := make([]byte, len(tcp.Payload))
			copy(payload, tcp.Payload)
			select {
			case conn.chMessage <- message{payload, &src}:
			case <-conn.die:
				return
			}
		}
	}
}

// ReadFrom implements the PacketConn ReadFrom method.
func (conn *tcpConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	var timer *time.Timer
	var deadline <-chan time.Time
	if d, ok := conn.readDeadline.Load().(time.Time); ok && !d.IsZero() {
		timer = time.NewTimer(time.Until(d))
		defer timer.Stop()
		deadline = timer.C
	}

	select {
	case <-deadline:
		return 0, nil, errTimeout
	case <-conn.die:
		return 0, nil, io.EOF
	case packet := <-conn.chMessage:
		n = copy(p, packet.bts)
		return n, packet.addr, nil
	}
}

// WriteTo implements the PacketConn WriteTo method.
func (conn *tcpConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	var deadline <-chan time.Time
	if d, ok := conn.writeDeadline.Load().(time.Time); ok && !d.IsZero() {
		timer := time.NewTimer(time.Until(d))
		defer timer.Stop()
		deadline = timer.C
	}

	select {
	case <-deadline:
		return 0, errTimeout
	case <-conn.die:
		return 0, io.EOF
	default:
		raddr, err := net.ResolveTCPAddr("tcp", addr.String())
		if err != nil {
			return 0, err
		}

		var lport int
		if conn.tcpconn != nil {
			lport = conn.tcpconn.LocalAddr().(*net.TCPAddr).Port
		} else {
			lport = conn.listener.Addr().(*net.TCPAddr).Port
		}

		conn.lockflow(addr, func(e *tcpFlow) {
			// if the flow doesn't have handle , assume this packet has lost, without notification
			if e.handle == nil {
				n = len(p)
				return
			}

			// build tcp header with local and remote port
			e.tcpHeader.SrcPort = layers.TCPPort(lport)
			e.tcpHeader.DstPort = layers.TCPPort(raddr.Port)
			e.tcpHeader.Window = conn.tcpFingerPrint.Window
			e.tcpHeader.Ack = e.ack
			e.tcpHeader.Seq = e.seq
			e.tcpHeader.PSH = true
			e.tcpHeader.ACK = true
			e.tcpHeader.Options = conn.tcpFingerPrint.Options
			makeOption(conn.tcpFingerPrint.Type, e.tcpHeader.Options, e.tsEcr)

			// build IP header with src & dst ip for TCP checksum
			if raddr.IP.To4() != nil {
				ip := &layers.IPv4{
					Protocol: layers.IPProtocolTCP,
					SrcIP:    e.handle.LocalAddr().(*net.IPAddr).IP.To4(),
					DstIP:    raddr.IP.To4(),
				}
				e.tcpHeader.SetNetworkLayerForChecksum(ip)
			} else {
				ip := &layers.IPv6{
					NextHeader: layers.IPProtocolTCP,
					SrcIP:      e.handle.LocalAddr().(*net.IPAddr).IP.To16(),
					DstIP:      raddr.IP.To16(),
				}
				e.tcpHeader.SetNetworkLayerForChecksum(ip)
			}

			e.buf.Clear()
			gopacket.SerializeLayers(e.buf, conn.opts, &e.tcpHeader, gopacket.Payload(p))
			if conn.tcpconn != nil {
				_, err = e.handle.Write(e.buf.Bytes())
			} else {
				_, err = e.handle.WriteToIP(e.buf.Bytes(), &net.IPAddr{IP: raddr.IP})
			}
			// increase seq in flow
			e.seq += uint32(len(p))
			n = len(p)
		})
	}
	return
}

// Close closes the connection.
func (conn *tcpConn) Close() error {
	var err error

	conn.dieOnce.Do(func() {
		// signal closing
		close(conn.die)

		// close all established tcp connections
		if conn.tcpconn != nil { // client
			setTTL(conn.tcpconn, 64)
			err = conn.tcpconn.Close()
		} else if conn.listener != nil {
			err = conn.listener.Close() // server
			conn.flowsLock.Lock()
			for k, v := range conn.flowTable {
				if v.conn != nil {
					setTTL(v.conn, 64)
					v.conn.Close()
				}
				delete(conn.flowTable, k)
			}
			conn.flowsLock.Unlock()
		}

		// close handles
		for k := range conn.handles {
			conn.handles[k].Close()
		}

		// delete iptable (Loop through all rules)
		if conn.iptables != nil {
			for _, rule := range conn.iprules {
				conn.iptables.Delete("filter", "OUTPUT", rule...)
			}
		}
		if conn.ip6tables != nil {
			for _, rule := range conn.ip6rules {
				conn.ip6tables.Delete("filter", "OUTPUT", rule...)
			}
		}

		// remove from the global list
		connListMu.Lock()
		connList.Remove(conn.elem)
		connListMu.Unlock()
	})
	return err
}

// LocalAddr returns the local network address.
func (conn *tcpConn) LocalAddr() net.Addr {
	if conn.tcpconn != nil {
		return conn.tcpconn.LocalAddr()
	} else if conn.listener != nil {
		return conn.listener.Addr()
	}
	return nil
}

// SetDeadline implements the Conn SetDeadline method.
func (conn *tcpConn) SetDeadline(t time.Time) error {
	if err := conn.SetReadDeadline(t); err != nil {
		return err
	}
	if err := conn.SetWriteDeadline(t); err != nil {
		return err
	}
	return nil
}

// SetReadDeadline implements the Conn SetReadDeadline method.
func (conn *tcpConn) SetReadDeadline(t time.Time) error {
	conn.readDeadline.Store(t)
	return nil
}

// SetWriteDeadline implements the Conn SetWriteDeadline method.
func (conn *tcpConn) SetWriteDeadline(t time.Time) error {
	conn.writeDeadline.Store(t)
	return nil
}

// SetDSCP sets the 6bit DSCP field in IPv4 header, or 8bit Traffic Class in IPv6 header.
func (conn *tcpConn) SetDSCP(dscp int) error {
	for k := range conn.handles {
		if err := setDSCP(conn.handles[k], dscp); err != nil {
			return err
		}
	}
	return nil
}

// SetReadBuffer sets the size of the operating system's receive buffer associated with the connection.
func (conn *tcpConn) SetReadBuffer(bytes int) error {
	var err error
	for k := range conn.handles {
		if err := conn.handles[k].SetReadBuffer(bytes); err != nil {
			return err
		}
	}
	return err
}

// SetWriteBuffer sets the size of the operating system's transmit buffer associated with the connection.
func (conn *tcpConn) SetWriteBuffer(bytes int) error {
	var err error
	for k := range conn.handles {
		if err := conn.handles[k].SetWriteBuffer(bytes); err != nil {
			return err
		}
	}
	return err
}

// Dial connects to the remote TCP port,
// and returns a single packet-oriented connection
func Dial(network, address string) (*TCPConn, error) {
	// remote address resolve
	raddr, err := net.ResolveTCPAddr(network, address)
	if err != nil {
		return nil, err
	}

	// AF_INET
	handle, err := net.DialIP("ip:tcp", nil, &net.IPAddr{IP: raddr.IP})
	if err != nil {
		return nil, err
	}

	// create an established tcp connection
	// will hack this tcp connection for packet transmission
	tcpconn, err := net.DialTCP(network, nil, raddr)
	if err != nil {
		return nil, err
	}

	// fields
	conn := new(tcpConn)
	conn.die = make(chan struct{})
	conn.flowTable = make(map[string]*tcpFlow)
	conn.tcpconn = tcpconn
	conn.chMessage = make(chan message)
	conn.lockflow(tcpconn.RemoteAddr(), func(e *tcpFlow) { e.conn = tcpconn })
	conn.handles = append(conn.handles, handle)
	conn.opts = gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	conn.tcpFingerPrint = fingerPrintLinux.Clone()

	// Apply BPF filter to only receive packets for this connection's port
	// This prevents the "thundering herd" problem where multiple processes
	// receive all packets, causing high CPU usage on idle processes.
	// Note: We use the local port of the established TCP connection.
	lportInt := tcpconn.LocalAddr().(*net.TCPAddr).Port
	if err := applyBPF(handle, lportInt); err != nil {
		// Log error but don't fail, fallback to userspace filtering
		// fmt.Println("Warning: failed to apply BPF filter:", err)
	}

	go conn.captureFlow(handle, lportInt)
	go conn.cleaner()

	// iptables
	err = setTTL(tcpconn, 1)
	if err != nil {
		conn.Close()
		return nil, err
	}

	// setup iptables only when it's the first connection
	if ipt, err := iptables.NewWithProtocol(iptables.ProtocolIPv4); err == nil {
		// Rule 1: Drop TTL=1 (Kernel ACKs)
		ttlRule := []string{"-m", "ttl", "--ttl-eq", "1", "-p", "tcp", "-d", raddr.IP.String(), "--dport", fmt.Sprint(raddr.Port), "-j", "DROP"}
		// Rule 2: Drop RST packets (Prevents Connection Reset by Kernel)
		rstRule := []string{"-p", "tcp", "--tcp-flags", "RST", "RST", "-d", raddr.IP.String(), "--dport", fmt.Sprint(raddr.Port), "-j", "DROP"}

		conn.iptables = ipt

        //_ = ipt.Delete("filter", "OUTPUT", rstRule...)
		//_ = ipt.Delete("filter", "OUTPUT", ttlRule...)

		// Insert RST Rule at position 1
		if exists, err := ipt.Exists("filter", "OUTPUT", rstRule...); err == nil {
			if !exists {
				// use Insert(..., 1, ...) to prepend
				if err = ipt.Insert("filter", "OUTPUT", 1, rstRule...); err == nil {
					conn.iprules = append(conn.iprules, rstRule)
				}
			}
		}

		// Insert TTL Rule at position 1 (pushes RST to 2, both are at top)
		if exists, err := ipt.Exists("filter", "OUTPUT", ttlRule...); err == nil {
			if !exists {
				if err = ipt.Insert("filter", "OUTPUT", 1, ttlRule...); err == nil {
					conn.iprules = append(conn.iprules, ttlRule)
				}
			}
		}
	}

	if ipt, err := iptables.NewWithProtocol(iptables.ProtocolIPv6); err == nil {
		// IPv6 Rules
		ttlRule := []string{"-m", "hl", "--hl-eq", "1", "-p", "tcp", "-d", raddr.IP.String(), "--dport", fmt.Sprint(raddr.Port), "-j", "DROP"}
		rstRule := []string{"-p", "tcp", "--tcp-flags", "RST", "RST", "-d", raddr.IP.String(), "--dport", fmt.Sprint(raddr.Port), "-j", "DROP"}

		conn.ip6tables = ipt

		if exists, err := ipt.Exists("filter", "OUTPUT", rstRule...); err == nil {
			if !exists {
				if err = ipt.Insert("filter", "OUTPUT", 1, rstRule...); err == nil {
					conn.ip6rules = append(conn.ip6rules, rstRule)
				}
			}
		}
		if exists, err := ipt.Exists("filter", "OUTPUT", ttlRule...); err == nil {
			if !exists {
				if err = ipt.Insert("filter", "OUTPUT", 1, ttlRule...); err == nil {
					conn.ip6rules = append(conn.ip6rules, ttlRule)
				}
			}
		}
	}

	// discard everything
	go io.Copy(ioutil.Discard, tcpconn)

	// push back to the global list and set the elem
	connListMu.Lock()
	conn.elem = connList.PushBack(conn)
	connListMu.Unlock()

	return wrapConn(conn), nil
}

// Listen acts like net.ListenTCP,
// and returns a single packet-oriented connection
func Listen(network, address string) (*TCPConn, error) {
	// fields
	conn := new(tcpConn)
	conn.flowTable = make(map[string]*tcpFlow)
	conn.die = make(chan struct{})
	conn.chMessage = make(chan message)
	conn.opts = gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	conn.tcpFingerPrint = fingerPrintLinux.Clone()

	// resolve address
	laddr, err := net.ResolveTCPAddr(network, address)
	if err != nil {
		return nil, err
	}

	// AF_INET
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	if laddr.IP == nil || laddr.IP.IsUnspecified() { // if address is not specified, capture on all ifaces
		var lasterr error
		for _, iface := range ifaces {
			if addrs, err := iface.Addrs(); err == nil {
				for _, addr := range addrs {
					if ipaddr, ok := addr.(*net.IPNet); ok {
						if handle, err := net.ListenIP("ip:tcp", &net.IPAddr{IP: ipaddr.IP}); err == nil {
							conn.handles = append(conn.handles, handle)
							// Apply BPF
							if err := applyBPF(handle, laddr.Port); err != nil {
								// Log or ignore
							}
							go conn.captureFlow(handle, laddr.Port)
						} else {
							lasterr = err
						}
					}
				}
			}
		}
		if len(conn.handles) == 0 {
			return nil, lasterr
		}
	} else {
		if handle, err := net.ListenIP("ip:tcp", &net.IPAddr{IP: laddr.IP}); err == nil {
			conn.handles = append(conn.handles, handle)
			// Apply BPF
			if err := applyBPF(handle, laddr.Port); err != nil {
				// Log or ignore
			}
			go conn.captureFlow(handle, laddr.Port)
		} else {
			return nil, err
		}
	}

	// start listening
	l, err := net.ListenTCP(network, laddr)
	if err != nil {
		for _, h := range conn.handles {
			h.Close()
		}
		return nil, err
	}

	conn.listener = l

	// start cleaner
	go conn.cleaner()

	// ---------------------------------------------------------------------
	// Helper：检查是否为 IPv6 通配符地址 (::)
	// ---------------------------------------------------------------------
	isIPv6Wildcard := func(addr *net.TCPAddr) bool {
		if addr.IP.To4() != nil {
			return false
		}
		for _, b := range addr.IP {
			if b != 0 {
				return false
			}
		}
		return true
	}

	// 1. 设置 IPv4 规则 (使用 Insert + RST)
	if ipt, err := iptables.NewWithProtocol(iptables.ProtocolIPv4); err == nil {
		var srcIP string
		// 如果监听 [::]，在 IPv4 iptables 中必须视为 0.0.0.0/0
		if isIPv6Wildcard(laddr) {
			srcIP = "0.0.0.0/0"
		} else if ip4 := laddr.IP.To4(); ip4 != nil {
			srcIP = ip4.String()
		} else {
			// 纯 IPv6 非通配符地址，通常不匹配 IPv4，但也设为通配以防万一
			srcIP = "0.0.0.0/0"
		}

		// TTL Rule
		ttlRule := []string{"-m", "ttl", "--ttl-eq", "1", "-p", "tcp", "-s", srcIP, "--sport", fmt.Sprint(laddr.Port), "-j", "DROP"}
		// RST Rule
		rstRule := []string{"-p", "tcp", "--tcp-flags", "RST", "RST", "-s", srcIP, "--sport", fmt.Sprint(laddr.Port), "-j", "DROP"}

		conn.iptables = ipt

        //_ = ipt.Delete("filter", "OUTPUT", rstRule...)
		//_ = ipt.Delete("filter", "OUTPUT", ttlRule...)

		// 插入 RST 规则
		if exists, err := ipt.Exists("filter", "OUTPUT", rstRule...); err == nil && !exists {
			if err = ipt.Insert("filter", "OUTPUT", 1, rstRule...); err == nil {
				conn.iprules = append(conn.iprules, rstRule)
			}
		}
		// 插入 TTL 规则
		if exists, err := ipt.Exists("filter", "OUTPUT", ttlRule...); err == nil && !exists {
			if err = ipt.Insert("filter", "OUTPUT", 1, ttlRule...); err == nil {
				conn.iprules = append(conn.iprules, ttlRule)
			}
		}
	}

	// 2. 设置 IPv6 规则
	if ipt, err := iptables.NewWithProtocol(iptables.ProtocolIPv6); err == nil {
		ttlRule := []string{"-m", "hl", "--hl-eq", "1", "-p", "tcp", "--sport", fmt.Sprint(laddr.Port), "-j", "DROP"}
		rstRule := []string{"-p", "tcp", "--tcp-flags", "RST", "RST", "--sport", fmt.Sprint(laddr.Port), "-j", "DROP"}

		conn.ip6tables = ipt

		if exists, err := ipt.Exists("filter", "OUTPUT", rstRule...); err == nil && !exists {
			if err = ipt.Insert("filter", "OUTPUT", 1, rstRule...); err == nil {
				conn.ip6rules = append(conn.ip6rules, rstRule)
			}
		}
		if exists, err := ipt.Exists("filter", "OUTPUT", ttlRule...); err == nil && !exists {
			if err = ipt.Insert("filter", "OUTPUT", 1, ttlRule...); err == nil {
				conn.ip6rules = append(conn.ip6rules, ttlRule)
			}
		}
	}

	// discard everything in original connection
	go func() {
		for {
			tcpconn, err := l.AcceptTCP()
			if err != nil {
				return
			}

			// if we cannot set TTL = 1, the only thing reasonable is panic
			if err := setTTL(tcpconn, 1); err != nil {
				panic(err)
			}

			// record net.Conn
			conn.lockflow(tcpconn.RemoteAddr(), func(e *tcpFlow) { e.conn = tcpconn })

			// discard everything
			go io.Copy(ioutil.Discard, tcpconn)
		}
	}()

	// push back to the global list and set the elem
	connListMu.Lock()
	conn.elem = connList.PushBack(conn)
	connListMu.Unlock()

	return wrapConn(conn), nil
}

// setTTL sets the Time-To-Live field on a given connection
func setTTL(c *net.TCPConn, ttl int) error {
	raw, err := c.SyscallConn()
	if err != nil {
		return err
	}
	addr := c.LocalAddr().(*net.TCPAddr)

	if addr.IP.To4() == nil {
		raw.Control(func(fd uintptr) {
			err = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_UNICAST_HOPS, ttl)
		})
	} else {
		raw.Control(func(fd uintptr) {
			err = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TTL, ttl)
		})
	}
	return err
}

// setDSCP sets the 6bit DSCP field in IPv4 header, or 8bit Traffic Class in IPv6 header.
func setDSCP(c *net.IPConn, dscp int) error {
	raw, err := c.SyscallConn()
	if err != nil {
		return err
	}
	addr := c.LocalAddr().(*net.IPAddr)

	if addr.IP.To4() == nil {
		raw.Control(func(fd uintptr) {
			err = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_TCLASS, dscp)
		})
	} else {
		raw.Control(func(fd uintptr) {
			err = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TOS, dscp<<2)
		})
	}
	return err
}

// wrapConn wraps a tcpConn in a TCPConn.
func wrapConn(conn *tcpConn) *TCPConn {
	// Set up a finalizer to ensure resources are cleaned up when the TCPConn is garbage collected
	wrapper := &TCPConn{tcpConn: conn}
	runtime.SetFinalizer(wrapper, func(wrapper *TCPConn) {
		wrapper.Close()
	})

	return wrapper
}

// applyBPF attaches a specific BPF filter based on the IP family of the socket.
// This eliminates the ambiguity of "Hybrid" filters.
// - For IPv4 Sockets: Uses dynamic IHL calculation to find TCP port (Handles Options).
// - For IPv6 Sockets: Uses direct offset lookup (Raw TCP payload).
func applyBPF(conn *net.IPConn, port int) error {
	f, err := conn.SyscallConn()
	if err != nil {
		return err
	}

	// 1. Determine IP Family from the local address
	addr := conn.LocalAddr().(*net.IPAddr)
	isIPv4 := addr.IP.To4() != nil
	targetPort := uint32(port)

	var filter []syscall.SockFilter

	if isIPv4 {
		// ---------------------------------------------------------
		// IPv4 ONLY Filter
		// Robust logic: Calculates IHL to skip IP header (handles Options)
		// ---------------------------------------------------------
		filter = []syscall.SockFilter{
			// 1. Load IP Header Length (IHL) * 4 into Register X
			//    Instruction: ldxb 4*([0]&0xf)
			//    This reads the first byte, masks low 4 bits, multiplies by 4.
			{Code: syscall.BPF_LDX | syscall.BPF_B | syscall.BPF_MSH, K: 0},

			// 2. Load 16-bit Destination Port at (Register X + 2)
			//    X is the length of IP header. X+2 is where DstPort sits in TCP header.
			{Code: syscall.BPF_LD | syscall.BPF_H | syscall.BPF_IND, K: 2},

			// 3. Compare with Target Port
			//    If Equal -> Jump to KEEP (Line 5). Else -> Fallthrough to DROP.
			{Code: syscall.BPF_JMP | syscall.BPF_JEQ | syscall.BPF_K, K: targetPort, Jt: 1, Jf: 0},

			// 4. DROP
			{Code: syscall.BPF_RET | syscall.BPF_K, K: 0},

			// 5. KEEP
			{Code: syscall.BPF_RET | syscall.BPF_K, K: 0xFFFFFFFF},
		}
	} else {
		// ---------------------------------------------------------
		// IPv6 ONLY Filter
		// Logic: AF_INET6 SOCK_RAW (IPPROTO_TCP) strips IPv6 header.
		// Data starts directly at TCP Header. DstPort is at Offset 2.
		// ---------------------------------------------------------
		filter = []syscall.SockFilter{
			// 1. Load 16-bit Destination Port at Offset 2
			{Code: syscall.BPF_LD | syscall.BPF_H | syscall.BPF_ABS, K: 2},

			// 2. Compare with Target Port
			//    If Equal -> Jump to KEEP (Line 4). Else -> Fallthrough to DROP.
			{Code: syscall.BPF_JMP | syscall.BPF_JEQ | syscall.BPF_K, K: targetPort, Jt: 1, Jf: 0},

			// 3. DROP
			{Code: syscall.BPF_RET | syscall.BPF_K, K: 0},

			// 4. KEEP
			{Code: syscall.BPF_RET | syscall.BPF_K, K: 0xFFFFFFFF},
		}
	}

	var sockErr error
	err = f.Control(func(fd uintptr) {
		prog := syscall.SockFprog{
			Len:    uint16(len(filter)),
			Filter: (*syscall.SockFilter)(unsafe.Pointer(&filter[0])),
		}

		_, _, errno := syscall.Syscall6(
			syscall.SYS_SETSOCKOPT,
			uintptr(fd),
			uintptr(syscall.SOL_SOCKET),
			uintptr(syscall.SO_ATTACH_FILTER),
			uintptr(unsafe.Pointer(&prog)),
			uintptr(unsafe.Sizeof(prog)),
			0,
		)
		if errno != 0 {
			sockErr = errno
		}
	})

	if err != nil {
		return err
	}
	if sockErr != nil {
		fmt.Printf("Warning: BPF Attach Failed: %v\n", sockErr)
	}
	return sockErr
}

// ---------------------------------------------------------------------
// Global Signal Handler for Graceful Shutdown
// ---------------------------------------------------------------------
func init() {
	// 启动一个协程监听系统信号
	go func() {
		// 创建一个接收信号的通道
		c := make(chan os.Signal, 1)

		// 监听 SIGINT (Ctrl+C) 和 SIGTERM (kill 默认信号)
		// 注意：SIGKILL (kill -9) 是无法捕获的
		signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)

		// 阻塞直到收到信号
		<-c
		//sig := <-c
		//fmt.Printf("\nReceived signal: %s. Cleaning up iptables rules...\n", sig)

		cleanupAll()

		// 退出程序
		os.Exit(0)
	}()
}

// cleanupAll 安全地关闭所有活跃连接并清理 iptables
func cleanupAll() {
	// 1. 获取所有连接的快照
	// 我们必须先复制一份，因为 conn.Close() 会尝试获取锁并从列表中删除元素，
	// 如果直接在持有锁的情况下遍历并 Close，会导致死锁。
	var conns []*tcpConn

	connListMu.Lock()
	for e := connList.Front(); e != nil; e = e.Next() {
		if c, ok := e.Value.(*tcpConn); ok {
			conns = append(conns, c)
		}
	}
	connListMu.Unlock()

	// 2. 逐个关闭
	for _, c := range conns {
		// Close 内部会调用 iptables.Delete 清理规则
		c.Close()
	}

	//fmt.Printf("Cleaned up %d connections.\n", len(conns))
}
