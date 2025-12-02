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
	"time"

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
	flag.Parse()

	// Handle interface alias
	finalIface := *ifaceName
	if finalIface == "" {
		finalIface = *ifaceNameShort
	}

	// 2. Config Loading / Generation
	targetConfig := *configPath
	if targetConfig == "" {
		// specific logic: if no flag, look for local, else generate random
		if _, err := os.Stat("config.json"); err == nil {
			targetConfig = "config.json"
			log.Println("No config flag provided, using existing 'config.json'")
		} else {
			targetConfig = fmt.Sprintf("config-example.json", time.Now().UnixNano())
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
	startHTTPServer(*port, *skipSSL, *proxyURL)
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
		// Normalize source (lowercase)
		routeMap[strings.ToLower(r.Source)] = targetURL
		log.Printf("Loaded Route: %s -> %s", r.Source, r.Target)
	}
}

// --- HTTP Redirector Logic ---

// loggingResponseWriter captures the status code for logging purposes
type loggingResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (lrw *loggingResponseWriter) WriteHeader(code int) {
	lrw.statusCode = code
	lrw.ResponseWriter.WriteHeader(code)
}

func startHTTPServer(port int, skipSSL bool, proxyAddr string) {
	// Configure Transport (Proxy + TLS settings)
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: skipSSL,
			// FORCE HTTP/1.1: This is critical.
			// The error "tls: user canceled" often happens when using httputil.ReverseProxy with HTTP/2
			// over certain proxies or against servers that reset H2 streams.
			NextProtos: []string{"http/1.1"},
		},
		ForceAttemptHTTP2: false,                     // Explicitly disable HTTP/2
		Proxy:             http.ProxyFromEnvironment, // Default fallback
	}

	if proxyAddr != "" {
		pURL, err := url.Parse(proxyAddr)
		if err != nil {
			log.Fatalf("Invalid proxy URL: %v", err)
		}
		transport.Proxy = http.ProxyURL(pURL)
		log.Printf("Using outbound proxy: %s", proxyAddr)
	}

	// Create the Reverse Proxy
	proxy := &httputil.ReverseProxy{
		Transport: transport,
		Director: func(req *http.Request) {
			mu.RLock()
			target, exists := routeMap[strings.ToLower(req.Host)]
			mu.RUnlock()

			if !exists {
				// If no match, we can't really forward it blindly without a target.
				// We'll log it, and the Transport will likely fail or loop.
				return
			}

			// 1. Rewrite URL Scheme and Host to target
			req.URL.Scheme = target.Scheme
			req.URL.Host = target.Host
			
			// 2. Rewrite Host header to target Host
			req.Host = target.Host

			// 3. STRICT REQUIREMENT: "Do not add any new headers"
			// httputil.ReverseProxy adds X-Forwarded-For by default. We must remove it.
			req.Header["X-Forwarded-For"] = nil
			
			// Note: We do NOT delete other headers, fulfilling "Do not remove existing headers"
		},
		// Ensure response is unmodified
		ModifyResponse: func(r *http.Response) error {
			return nil
		},
		// Custom error handler to avoid disclosing internal info
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("[ERROR] Proxy Error for %s: %v", r.Host, err)
			w.WriteHeader(http.StatusBadGateway)
		},
	}

	// Logging Wrapper
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		
		// Log incoming request
		log.Printf("[HTTP-IN] %s %s %s", r.Method, r.Host, r.URL.Path)

		lrw := &loggingResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		proxy.ServeHTTP(lrw, r)

		// Log completed request
		log.Printf("[HTTP-OUT] %s %s %s -> Status: %d (%v)", r.Method, r.Host, r.URL.Path, lrw.statusCode, time.Since(start))
	})

	log.Printf("HTTP Redirector listening on port %d...", port)
	log.Printf("SSL Verification Skipped: %v", skipSSL)
	
	// Use the logging handler instead of the raw proxy
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
		// Check for IPv4
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
		// DNS names end with a dot usually
		name := strings.TrimSuffix(strings.ToLower(q.Name), ".")

		mu.RLock()
		_, exists := routeMap[name]
		mu.RUnlock()

		if exists && q.Qtype == dns.TypeA {
			log.Printf("[DNS] Match: %s -> Returning Interface IP", name)
			// Return Interface IP
			rr, err := dns.NewRR(fmt.Sprintf("%s A %s", q.Name, interfaceIP.String()))
			if err == nil {
				m.Answer = append(m.Answer, rr)
			}
		} else {
			// Forward to System/Recursive Resolver
			log.Printf("[DNS] No Match/Not A-Record: %s -> System Lookup", name)
			resp := systemDNSLookup(q)
			if resp != nil {
				m.Answer = resp
			}
		}
	}

	w.WriteMsg(m)
}

// systemDNSLookup uses the local system's resolver (net.LookupIP)
func systemDNSLookup(q dns.Question) []dns.RR {
	name := strings.TrimSuffix(q.Name, ".")
	
	// Use Go's net package to look up IP (uses system resolver)
	ips, err := net.LookupIP(name)
	if err != nil {
		return nil
	}

	var answers []dns.RR
	for _, ip := range ips {
		// Filter based on query type (A vs AAAA)
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