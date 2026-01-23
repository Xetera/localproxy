package proxy

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"
)

type TCPProxy struct {
	listeners map[int]net.Listener
	routes    map[int]Route
	mu        sync.RWMutex
	ctx       context.Context
	cancel    context.CancelFunc
}

func NewTCPProxy() *TCPProxy {
	ctx, cancel := context.WithCancel(context.Background())
	return &TCPProxy{
		listeners: make(map[int]net.Listener),
		routes:    make(map[int]Route),
		ctx:       ctx,
		cancel:    cancel,
	}
}

func (tp *TCPProxy) UpdateRoutes(routes []Route) {
	tp.mu.Lock()
	defer tp.mu.Unlock()

	newRoutes := make(map[int]Route)
	for _, r := range routes {
		if r.TCPPort > 0 {
			newRoutes[r.TCPPort] = r
		}
	}

	for port := range tp.routes {
		if _, exists := newRoutes[port]; !exists {
			tp.stopListener(port)
		}
	}

	for port, route := range newRoutes {
		if _, exists := tp.routes[port]; !exists {
			go tp.startListener(port, route)
		}
	}

	tp.routes = newRoutes
}

func (tp *TCPProxy) startListener(port int, route Route) {
	addr := fmt.Sprintf(":%d", port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("tcp proxy: failed to listen on %s: %v", addr, err)
		return
	}

	tp.mu.Lock()
	tp.listeners[port] = listener
	tp.mu.Unlock()

	log.Printf("tcp proxy: listening on %s -> %s:%d", addr, route.Host, route.Port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-tp.ctx.Done():
				return
			default:
				log.Printf("tcp proxy: accept error on port %d: %v", port, err)
				continue
			}
		}

		go tp.handleConnection(conn, route)
	}
}

func (tp *TCPProxy) stopListener(port int) {
	if listener, exists := tp.listeners[port]; exists {
		listener.Close()
		delete(tp.listeners, port)
		log.Printf("tcp proxy: stopped listening on port %d", port)
	}
}

func (tp *TCPProxy) handleConnection(clientConn net.Conn, route Route) {
	defer clientConn.Close()

	targetAddr := net.JoinHostPort(route.Host, fmt.Sprintf("%d", route.Port))
	targetConn, err := net.DialTimeout("tcp", targetAddr, 10*time.Second)
	if err != nil {
		log.Printf("tcp proxy: failed to connect to %s: %v", targetAddr, err)
		return
	}
	defer targetConn.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(targetConn, clientConn)
		targetConn.(*net.TCPConn).CloseWrite()
	}()

	go func() {
		defer wg.Done()
		io.Copy(clientConn, targetConn)
		clientConn.(*net.TCPConn).CloseWrite()
	}()

	wg.Wait()
}

func (tp *TCPProxy) Stop() {
	tp.cancel()

	tp.mu.Lock()
	defer tp.mu.Unlock()

	for port, listener := range tp.listeners {
		listener.Close()
		log.Printf("tcp proxy: stopped listener on port %d", port)
	}

	tp.listeners = make(map[int]net.Listener)
	tp.routes = make(map[int]Route)
}
