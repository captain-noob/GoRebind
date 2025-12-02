package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"

	"github.com/miekg/dns"
)

// ConfigRoute represents a single mapping rule
type ConfigRoute struct {
	Source string `json:"source"`
	Target string `json:"target"`
}

var (
	// Global map for O(1) lookups during high traffic
	routeMap = make(map[string]*url.URL)
	mu       sync.RWMutex

	// Interface IP for DNS responses
	interfaceIP net.IP

	// Global verbose flag
	verboseMode bool
)

func main() {
	// 1. Parse Flags
	configPath := flag.String("config", "", "Path to config file")
	skipSSL := flag.Bool("skip-ssl-verify", true, "Skip TLS verification")
	port := flag.Int("port", 80, "Port for HTTP server")
	proxyURL := flag.String("proxy", "", "Optional outbound HTTP proxy URL")
	enableDNS := flag.Bool("dns", false, "Enable DNS server functionality")
	ifaceName := flag.String("interface", "", "Network interface name (required for DNS)")
	ifaceNameShort := flag.String("I", "", "Alias for -interface")
	verbose := flag.Bool("verbose", false, "Enable verbose logging for DNS misses")
	forceH2 := flag.Bool("http2", false, "Force enable HTTP/2 (may cause 'tls: user canceled' errors on some proxies)")
	flag.Parse()

	// Set global verbose state
	verboseMode = *verbose

	// Handle interface alias
	finalIface := *ifaceName
	if finalIface == "" {
		finalIface = *ifaceNameShort
	}

	// 2. Config Loading / Generation
	targetConfig := *configPath
	if targetConfig == "" {
		if _, err := os.Stat("config.json"); err == nil {
			targetConfig = "config.json"
			log.Println("No config flag provided, using existing 'config.json'")
		} else {
			targetConfig = "config-example.json"
			createDummyConfig(targetConfig)
			log.Printf("Created random config file: %s\n", targetConfig)
		}
	}

	loadConfig(targetConfig)

	// 3. DNS Server Setup (Optional)
	if *enableDNS {
		if finalIface == "" {
			log.Fatal("Error: -interface or -I is required when -dns is enabled")
		}

		var err error
		interfaceIP, err = getInterfaceIP(finalIface)
		if err != nil {
			log.Fatalf("Error getting IP for interface %s: %v", finalIface, err)
		}
		log.Printf("DNS Server enabled. Responding with IP %s for matched hosts.", interfaceIP.String())

		go startDNSServer()
	}

	// 4. HTTP Redirector Setup
	startHTTPServer(*port, *skipSSL, *proxyURL, *forceH2)
}

// --- Configuration Logic ---

func createDummyConfig(filename string) {
	dummy := []ConfigRoute{
		{Source: "example.local", Target: "https://www.google.com"},
		{Source: "api.local", Target: "http://127.0.0.1:8080"},
	}
	file, _ := json.MarshalIndent(dummy, "", "  ")
	_ = os.WriteFile(filename, file, 0644)
}

func loadConfig(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("Failed to read config: %v", err)
	}

	var routes []ConfigRoute
	if err := json.Unmarshal(data, &routes); err != nil {
		log.Fatalf("Invalid JSON config: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	for _, r := range routes {
		targetURL, err := url.Parse(r.Target)
		if err != nil {
			log.Printf("Warning: Skipping invalid target URL %s: %v", r.Target, err)
			continue
		}
		routeMap[strings.ToLower(r.Source)] = targetURL
		log.Printf("Loaded Route: %s -> %s", r.Source, r.Target)
	}
}

// --- HTTP Redirector Logic ---

type loggingResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (lrw *loggingResponseWriter) WriteHeader(code int) {
	lrw.statusCode = code
	lrw.ResponseWriter.WriteHeader(code)
}

func startHTTPServer(port int, skipSSL bool, proxyAddr string, enableH2 bool) {

	// Determine TLS ALPN protocols
	var nextProtos []string
	if !enableH2 {
		// FORCE HTTP/1.1 if H2 is disabled (prevents upgrade attempts)
		nextProtos = []string{"http/1.1"}
	}
	// If enableH2 is true, we leave nextProtos as nil,
	// which allows Go to negotiate ["h2", "http/1.1"] automatically.

	// Determine TLSNextProto map
	var tlsNextProto map[string]func(authority string, c *tls.Conn) http.RoundTripper
	if !enableH2 {
		// EMPTY MAP disables H2 support in the transport
		tlsNextProto = make(map[string]func(authority string, c *tls.Conn) http.RoundTripper)
	}
	// If enableH2 is true, we leave it nil, which uses Go's default (supporting H2)

	// Configure Transport
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: skipSSL,
			NextProtos:         nextProtos,
		},
		TLSNextProto:      tlsNextProto, // The switch for ALPN support
		ForceAttemptHTTP2: enableH2,     // The switch for H2C/Upgrades
		Proxy:             http.ProxyFromEnvironment,
	}

	if proxyAddr != "" {
		pURL, err := url.Parse(proxyAddr)
		if err != nil {
			log.Fatalf("Invalid proxy URL: %v", err)
		}
		transport.Proxy = http.ProxyURL(pURL)
		log.Printf("Using outbound proxy: %s", proxyAddr)
	}

	proxy := &httputil.ReverseProxy{
		Transport: transport,
		Director: func(req *http.Request) {
			mu.RLock()
			target, exists := routeMap[strings.ToLower(req.Host)]
			mu.RUnlock()

			if !exists {
				return
			}

			req.URL.Scheme = target.Scheme
			req.URL.Host = target.Host
			req.Host = target.Host
			req.Header["X-Forwarded-For"] = nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			if err != nil && err.Error() != "context canceled" {
				log.Printf("[ERROR] Proxy Error for %s: %v", r.Host, err)
			}
			w.WriteHeader(http.StatusBadGateway)
		},
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("[HTTP-IN] %s %s %s", r.Method, r.Host, r.URL.Path)
		lrw := &loggingResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		proxy.ServeHTTP(lrw, r)
	})

	log.Printf("HTTP Redirector listening on port %d...", port)
	log.Printf("HTTP/2 Enabled: %v", enableH2)

	if err := http.ListenAndServe(fmt.Sprintf(":%d", port), handler); err != nil {
		log.Fatal(err)
	}
}

// --- DNS Server Logic ---

func getInterfaceIP(name string) (net.IP, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil, err
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}

	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.To4(), nil
			}
		}
	}
	return nil, fmt.Errorf("no IPv4 address found on interface %s", name)
}

func startDNSServer() {
	dns.HandleFunc(".", handleDNSRequest)
	server := &dns.Server{Addr: ":53", Net: "udp"}
	log.Println("DNS Server listening on UDP :53...")
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Failed to start DNS server: %v", err)
	}
}

func handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false

	if r.Opcode == dns.OpcodeQuery && len(r.Question) > 0 {
		q := r.Question[0]
		name := strings.TrimSuffix(strings.ToLower(q.Name), ".")

		mu.RLock()
		_, exists := routeMap[name]
		mu.RUnlock()

		if exists && q.Qtype == dns.TypeA {
			log.Printf("[DNS] Match: %s -> Returning Interface IP", name)
			rr, err := dns.NewRR(fmt.Sprintf("%s A %s", q.Name, interfaceIP.String()))
			if err == nil {
				m.Answer = append(m.Answer, rr)
			}
		} else {
			if verboseMode {
				log.Printf("[DNS] No Match/Not A-Record: %s -> System Lookup", name)
			}
			resp := systemDNSLookup(q)
			if resp != nil {
				m.Answer = resp
			}
		}
	}

	w.WriteMsg(m)
}

func systemDNSLookup(q dns.Question) []dns.RR {
	name := strings.TrimSuffix(q.Name, ".")

	ips, err := net.LookupIP(name)
	if err != nil {
		return nil
	}

	var answers []dns.RR
	for _, ip := range ips {
		if q.Qtype == dns.TypeA && ip.To4() != nil {
			rr, _ := dns.NewRR(fmt.Sprintf("%s A %s", q.Name, ip.String()))
			answers = append(answers, rr)
		} else if q.Qtype == dns.TypeAAAA && ip.To4() == nil {
			rr, _ := dns.NewRR(fmt.Sprintf("%s AAAA %s", q.Name, ip.String()))
			answers = append(answers, rr)
		}
	}
	return answers
}
