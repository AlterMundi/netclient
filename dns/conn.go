package dns

import (
	"fmt"
	"net"
	"sync"
	"time"

	"golang.org/x/exp/slog"
)

const (
	// Maximum idle connections per server address.
	maxIdleConnsPerServer = 8
	// Maximum time a connection can sit idle in the pool before being closed.
	maxConnIdleTime = 30 * time.Second
	// Timeout for dialing new UDP connections.
	dialTimeout = 3 * time.Second
)

// pooledConn wraps a UDP connection with metadata for idle tracking.
type pooledConn struct {
	conn      *net.UDPConn
	idleSince time.Time
}

// boundedConnPool is a channel-based connection pool with a fixed upper bound.
// Unlike sync.Pool, evicted connections are explicitly closed to prevent FD leaks.
type boundedConnPool struct {
	mu       sync.Mutex
	pools    map[string]chan *pooledConn
	dialAddr map[string]*net.UDPAddr // cached parsed addresses
}

func newBoundedConnPool() *boundedConnPool {
	return &boundedConnPool{
		pools:    make(map[string]chan *pooledConn),
		dialAddr: make(map[string]*net.UDPAddr),
	}
}

// resolveAddr parses serverAddr into a *net.UDPAddr, caching the result.
// Uses net.ResolveUDPAddr only once per address; subsequent calls use cache.
func (p *boundedConnPool) resolveAddr(serverAddr string) (*net.UDPAddr, error) {
	p.mu.Lock()
	if addr, ok := p.dialAddr[serverAddr]; ok {
		p.mu.Unlock()
		return addr, nil
	}
	p.mu.Unlock()

	// Parse the address. For IP:port strings (the common case), this does
	// NOT trigger a DNS lookup. It only does DNS if serverAddr contains a
	// hostname, which is unlikely but handled safely outside any hot path.
	addr, err := net.ResolveUDPAddr("udp", serverAddr)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", serverAddr, err)
	}

	p.mu.Lock()
	p.dialAddr[serverAddr] = addr
	p.mu.Unlock()
	return addr, nil
}

// getPool returns the channel-based pool for a server, creating it if needed.
func (p *boundedConnPool) getPool(serverAddr string) chan *pooledConn {
	p.mu.Lock()
	defer p.mu.Unlock()
	ch, ok := p.pools[serverAddr]
	if !ok {
		ch = make(chan *pooledConn, maxIdleConnsPerServer)
		p.pools[serverAddr] = ch
	}
	return ch
}

// get retrieves a pooled connection or dials a new one.
func (p *boundedConnPool) get(serverAddr string) (*net.UDPConn, error) {
	ch := p.getPool(serverAddr)

	// Drain stale connections and try to find a valid one.
	for {
		select {
		case pc := <-ch:
			if time.Since(pc.idleSince) > maxConnIdleTime {
				pc.conn.Close()
				continue
			}
			return pc.conn, nil
		default:
			// Pool empty, dial a new connection.
			return p.dial(serverAddr)
		}
	}
}

// dial creates a new UDP connection to serverAddr.
func (p *boundedConnPool) dial(serverAddr string) (*net.UDPConn, error) {
	addr, err := p.resolveAddr(serverAddr)
	if err != nil {
		return nil, err
	}

	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", serverAddr, err)
	}
	return conn, nil
}

// put returns a connection to the pool, or closes it if the pool is full.
func (p *boundedConnPool) put(serverAddr string, conn *net.UDPConn) {
	if conn == nil {
		return
	}
	ch := p.getPool(serverAddr)
	pc := &pooledConn{conn: conn, idleSince: time.Now()}
	select {
	case ch <- pc:
		// Returned to pool.
	default:
		// Pool full — close the connection to avoid FD leak.
		conn.Close()
	}
}

// discard closes a connection without returning it to the pool.
// Use this when a connection is known to be broken (e.g. after an I/O error).
func (p *boundedConnPool) discard(conn *net.UDPConn) {
	if conn != nil {
		conn.Close()
	}
}

// closeAll drains and closes all pooled connections.
func (p *boundedConnPool) closeAll() {
	p.mu.Lock()
	pools := p.pools
	p.pools = make(map[string]chan *pooledConn)
	p.dialAddr = make(map[string]*net.UDPAddr)
	p.mu.Unlock()

	for _, ch := range pools {
		close(ch)
		for pc := range ch {
			pc.conn.Close()
		}
	}
	slog.Info("DNS connection pool closed")
}
