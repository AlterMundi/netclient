package dns

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/models"
	"github.com/miekg/dns"
	"golang.org/x/exp/slog"
)

const (
	ttlTimeout = 3600

	// Maximum concurrent upstream DNS queries to prevent goroutine explosion.
	maxConcurrentQueries = 64

	// Circuit breaker: after this many consecutive failures for a server,
	// skip it for backoffDuration before retrying.
	circuitBreakerThreshold = 5
	circuitBreakerBackoff   = 10 * time.Second
)

var dnsMapMutex sync.RWMutex // used to mutex functions of the DNS

// querySemaphore limits concurrent upstream DNS exchanges.
var querySemaphore = make(chan struct{}, maxConcurrentQueries)

// circuitBreaker tracks consecutive failures per upstream server.
type circuitBreaker struct {
	mu       sync.Mutex
	failures map[string]int
	backoff  map[string]time.Time
}

var breaker = &circuitBreaker{
	failures: make(map[string]int),
	backoff:  make(map[string]time.Time),
}

// isOpen returns true if the server is in backoff (circuit is open).
func (cb *circuitBreaker) isOpen(server string) bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	until, ok := cb.backoff[server]
	if !ok {
		return false
	}
	if time.Now().After(until) {
		// Backoff expired, allow a probe.
		delete(cb.backoff, server)
		cb.failures[server] = circuitBreakerThreshold - 1 // one more failure re-opens
		return false
	}
	return true
}

// recordFailure increments consecutive failures; opens circuit if threshold hit.
func (cb *circuitBreaker) recordFailure(server string) {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.failures[server]++
	if cb.failures[server] >= circuitBreakerThreshold {
		cb.backoff[server] = time.Now().Add(circuitBreakerBackoff)
		slog.Warn("DNS circuit breaker opened", "server", server, "backoff", circuitBreakerBackoff)
	}
}

// recordSuccess resets failure count for a server.
func (cb *circuitBreaker) recordSuccess(server string) {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	delete(cb.failures, server)
	delete(cb.backoff, server)
}

// droppedQueries counts queries dropped due to concurrency limit (observable metric).
var droppedQueries atomic.Int64

var (
	ErrNXDomain      = errors.New("non existent domain")
	ErrNoQTypeRecord = errors.New("domain exists but no record matching the question type")
	dnsUDPConnPool   = newBoundedConnPool()
)

type DNSResolver struct {
	DnsEntriesCacheStore map[string]dns.RR
	DnsEntriesCacheMap   map[string][]dnsRecord
}

var DnsResolver *DNSResolver

func init() {
	DnsResolver = &DNSResolver{
		DnsEntriesCacheStore: make(map[string]dns.RR),
		DnsEntriesCacheMap:   make(map[string][]dnsRecord),
	}
}

// GetInstance
func GetDNSResolverInstance() *DNSResolver {
	return DnsResolver
}

// ServeDNS handles a DNS request
func handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	reply := &dns.Msg{}
	reply.SetReply(r)
	reply.RecursionAvailable = true
	reply.RecursionDesired = true
	reply.Rcode = dns.RcodeSuccess
	logger.Log(4, fmt.Sprintf("resolving dns query %s", r.Question[0].Name))

	// Snapshot config once per request to avoid repeated RLock acquisition.
	nc := config.Netclient()

	if nc.CurrGwNmIP != nil {
		gwIP := nc.CurrGwNmIP.String()
		logger.Log(4, fmt.Sprintf(
			"connected to gw, forwarding dns query %s to gw %s",
			r.Question[0].Name, gwIP),
		)

		resp, err := exchangeDNSQueryWithPool(r, gwIP)
		if err != nil {
			logger.Log(4, fmt.Sprintf("failed to resolve dns query %s with gw %s: %v", r.Question[0].Name, gwIP, err))
		} else {
			logger.Log(4, fmt.Sprintf("resolved dns query %s with gw %s: %v", r.Question[0].Name, gwIP, resp.Answer))
			reply.Authoritative = resp.Authoritative
			reply.Answer = append(reply.Answer, resp.Answer...)
		}
	} else {
		query := canonicalizeDomainForMatching(r.Question[0].Name)
		currServer := config.GetServer(config.CurrServer)
		if currServer == nil {
			reply.Rcode = dns.RcodeServerFailure
		} else {
			// query matches default domain, resolve with local records
			logger.Log(4, fmt.Sprintf("resolving dns query %s with local records", r.Question[0].Name))

			resp, err := GetDNSResolverInstance().Lookup(r)
			if err != nil {
				logger.Log(4, fmt.Sprintf("failed to resolve dns query %s with local records: %v", r.Question[0].Name, err))
			} else {
				logger.Log(4, fmt.Sprintf("resolved dns query %s with local records: %v", r.Question[0].Name, resp))
				reply.Authoritative = true
				reply.Answer = append(reply.Answer, resp)
			}
			if len(reply.Answer) == 0 {
				bestMatchNameservers := findBestMatch(query, currServer.DnsNameservers)
				for _, nameserver := range bestMatchNameservers {
					if nameserver.IsFallback {
						continue
					}
					var queryResolved bool
					for _, ns := range nameserver.IPs {
						logger.Log(4, fmt.Sprintf("found best match %s, forwarding dns query %s to nameserver %s", nameserver.MatchDomain, r.Question[0].Name, ns))

						resp, err := exchangeDNSQueryWithPool(r, ns)
						if err != nil || resp == nil || len(resp.Answer) == 0 {
							if err != nil {
								logger.Log(4, fmt.Sprintf("failed to resolve dns query %s with nameserver %s: %v", r.Question[0].Name, ns, err))
							} else {
								logger.Log(4, fmt.Sprintf("failed to resolve dns query %s with nameserver %s: no answer", r.Question[0].Name, ns))
							}
							continue
						}

						if resp.Rcode != dns.RcodeSuccess {
							logger.Log(4, fmt.Sprintf("failed to resolve dns query %s with nameserver %s: rcode %d", r.Question[0].Name, ns, resp.Rcode))
							continue
						}

						if len(resp.Answer) > 0 {
							logger.Log(4, fmt.Sprintf("resolved dns query %s with nameserver %s: %v", r.Question[0].Name, ns, resp.Answer))
							reply.Answer = append(reply.Answer, resp.Answer...)
							reply.Authoritative = resp.Authoritative
							queryResolved = true
							break
						}
					}
					if queryResolved {
						break
					}
				}

				logger.Log(4, fmt.Sprintf("failed to resolve dns query %s with configured nameservers, falling back to fallback nameservers", r.Question[0].Name))

				for _, nameserver := range bestMatchNameservers {
					if nameserver.IsFallback {
						var queryResolved bool
						for _, ns := range nameserver.IPs {
							logger.Log(4, fmt.Sprintf("forwarding dns query %s to fallback nameserver %s", r.Question[0].Name, ns))

							resp, err := exchangeDNSQueryWithPool(r, ns)
							if err != nil || resp == nil || len(resp.Answer) == 0 {
								if err != nil {
									logger.Log(4, fmt.Sprintf("failed to resolve dns query %s with fallback nameserver %s: %v", r.Question[0].Name, ns, err))
								} else {
									logger.Log(4, fmt.Sprintf("failed to resolve dns query %s with fallback nameserver %s: no answer", r.Question[0].Name, ns))
								}
								continue
							}

							if resp.Rcode != dns.RcodeSuccess {
								logger.Log(4, fmt.Sprintf("failed to resolve dns query %s with fallback nameserver %s: rcode %d", r.Question[0].Name, ns, resp.Rcode))
								continue
							}

							if len(resp.Answer) > 0 {
								logger.Log(4, fmt.Sprintf("resolved dns query %s with fallback nameserver %s: %v", r.Question[0].Name, ns, resp.Answer))
								reply.Answer = append(reply.Answer, resp.Answer...)
								reply.Authoritative = resp.Authoritative
								queryResolved = true
								break
							}
						}
						if queryResolved {
							break
						}
					}
				}
			}
		}
	}

	_ = w.WriteMsg(reply)
}

// Register A record
func (d *DNSResolver) RegisterA(record dnsRecord) error {
	dnsMapMutex.Lock()
	defer dnsMapMutex.Unlock()

	r := new(dns.A)
	r.Hdr = dns.RR_Header{Name: dns.Fqdn(record.Name), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttlTimeout}
	r.A = net.ParseIP(record.RData)

	d.DnsEntriesCacheStore[buildDNSEntryKey(record.Name, record.Type)] = r

	slog.Debug("registering A record successfully", "Info", d.DnsEntriesCacheStore[buildDNSEntryKey(record.Name, record.Type)])

	return nil
}

// Register AAAA record
func (d *DNSResolver) RegisterAAAA(record dnsRecord) error {
	dnsMapMutex.Lock()
	defer dnsMapMutex.Unlock()

	r := new(dns.AAAA)
	r.Hdr = dns.RR_Header{Name: dns.Fqdn(record.Name), Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttlTimeout}
	r.AAAA = net.ParseIP(record.RData)

	d.DnsEntriesCacheStore[buildDNSEntryKey(record.Name, record.Type)] = r

	slog.Debug("registering AAAA record successfully", "Info", d.DnsEntriesCacheStore[buildDNSEntryKey(record.Name, record.Type)])

	return nil
}

// Lookup DNS entry in local directory
func (d *DNSResolver) Lookup(m *dns.Msg) (dns.RR, error) {
	dnsMapMutex.RLock()
	defer dnsMapMutex.RUnlock()
	q := m.Question[0]
	r, ok := d.DnsEntriesCacheStore[buildDNSEntryKey(strings.TrimSuffix(q.Name, "."), q.Qtype)]
	if !ok {
		switch q.Qtype {
		case dns.TypeA:
			_, ok = d.DnsEntriesCacheStore[buildDNSEntryKey(strings.TrimSuffix(q.Name, "."), dns.TypeAAAA)]
			if ok {
				// aware but no ipv6 address
				return nil, ErrNoQTypeRecord
			}
		case dns.TypeAAAA:
			_, ok = d.DnsEntriesCacheStore[buildDNSEntryKey(strings.TrimSuffix(q.Name, "."), dns.TypeA)]
			if ok {
				// aware but no ipv4 address
				return nil, ErrNoQTypeRecord
			}
		}

		return nil, ErrNXDomain
	}

	return r, nil
}

func exchangeDNSQueryWithPool(r *dns.Msg, ns string) (*dns.Msg, error) {
	// Normalize IPv6 if needed
	if strings.Contains(ns, ":") && !strings.HasPrefix(ns, "[") {
		ns = "[" + ns + "]"
	}
	serverAddr := ns + ":53"

	// Circuit breaker: skip servers in backoff.
	if breaker.isOpen(serverAddr) {
		return nil, fmt.Errorf("circuit breaker open for %s", serverAddr)
	}

	// Concurrency limiter: drop query if too many in-flight.
	select {
	case querySemaphore <- struct{}{}:
		defer func() { <-querySemaphore }()
	default:
		droppedQueries.Add(1)
		return nil, fmt.Errorf("DNS concurrency limit reached (%d), dropping query", maxConcurrentQueries)
	}

	conn, err := dnsUDPConnPool.get(serverAddr)
	if err != nil {
		breaker.recordFailure(serverAddr)
		return nil, err
	}

	dnsConn := &dns.Conn{
		Conn:    conn,
		UDPSize: dns.DefaultMsgSize,
	}

	client := &dns.Client{Net: "udp", Timeout: time.Second * 3}
	resp, _, err := client.ExchangeWithConn(r, dnsConn)
	if err != nil {
		// Connection is likely broken — discard instead of returning to pool.
		dnsUDPConnPool.discard(conn)
		breaker.recordFailure(serverAddr)
		return nil, err
	}

	// Success — return connection to pool and reset circuit breaker.
	dnsUDPConnPool.put(serverAddr, conn)
	breaker.recordSuccess(serverAddr)
	return resp, nil
}

func findBestMatch(domain string, nameservers []models.Nameserver) []models.Nameserver {
	var bestMatch []models.Nameserver
	bestScore := -1

	for _, nameserver := range nameservers {
		matchDomain := canonicalizeDomainForMatching(nameserver.MatchDomain)

		if strings.HasSuffix(domain, matchDomain) {
			currScore := strings.Count(matchDomain, ".")

			if currScore > bestScore {
				bestMatch = []models.Nameserver{nameserver}
				bestScore = currScore
			} else if currScore == bestScore {
				bestMatch = append(bestMatch, nameserver)
			}
		}
	}

	return bestMatch
}

func canonicalizeDomainForMatching(domain string) string {
	if !strings.HasPrefix(domain, ".") {
		domain = "." + domain
	}

	if !strings.HasSuffix(domain, ".") {
		domain = domain + "."
	}

	return domain
}
