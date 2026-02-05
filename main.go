package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/goccy/go-yaml"
	"github.com/miekg/dns"
)

type Config struct {
	Wordlists []string `yaml:"wordlists"`
}

type CacheEntry struct {
	msg       *dns.Msg
	ExpiresAt time.Time
}

type Cache struct {
	cachedDomains map[string]CacheEntry
	mu            sync.RWMutex
}

var dnsClient = &dns.Client{
	Net:     "udp",
	Timeout: 2 * time.Second,
}

var blacklistMap = make(map[string]struct{})

func fetchWordlists() {
	path := "./config.yaml"
	file := "blacklist.txt"
	uniqueDomains := make(map[string]any)
	data, _ := os.ReadFile(path)

	var cfg Config
	yaml.Unmarshal(data, &cfg)

	for _, url := range cfg.Wordlists {
		res, err := http.Get(url)
		if err != nil {
			log.Printf("Error fetching %s: %v", url, err)
			continue
		}

		body, err := io.ReadAll(res.Body)
		res.Body.Close()
		if err != nil {
			log.Fatal(err)
		}

		lines := strings.SplitSeq(string(body), "\n")
		for line := range lines {
			line = strings.TrimSpace(line)
			line = strings.TrimPrefix(line, "0.0.0.0 ")
			line = strings.TrimPrefix(line, "||")
			line = strings.TrimSuffix(line, "^")

			if line != "" && !strings.HasPrefix(line, "#") {
				uniqueDomains[line] = struct{}{}
			}
		}
	}

	var finalOutput strings.Builder
	for domain := range uniqueDomains {
		finalOutput.WriteString(domain + "\n")
	}

	err := os.WriteFile(file, []byte(finalOutput.String()), 0644)
	if err != nil {
		log.Fatal(err)
	}
}

func loadBlacklistFile(filepath string) {
	data, _ := os.ReadFile(filepath)
	lines := strings.SplitSeq(string(data), "\n")

	for line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			domain := strings.ToLower(strings.TrimSuffix(line, "."))
			blacklistMap[domain] = struct{}{}
		}
	}
}

func isBlacklisted(r *dns.Msg) bool {
	if len(r.Question) == 0 {
		return false
	}
	domain := strings.ToLower(strings.TrimSuffix(r.Question[0].Name, "."))
	_, found := blacklistMap[domain]
	return found
}

func cacheKey(r *dns.Msg) string {
	if len(r.Question) == 0 {
		return ""
	}
	requestDetails := r.Question[0]
	return requestDetails.Name + ":" + dns.TypeToString[requestDetails.Qtype]
}

var cache = &Cache{
	cachedDomains: make(map[string]CacheEntry),
}

func getShortestTTL(m *dns.Msg) time.Duration {
	var minTTL uint32 = 3600
	if len(m.Answer) == 0 {
		return 30 * time.Second
	}

	for _, rr := range m.Answer {
		if rr.Header().Ttl < minTTL {
			minTTL = rr.Header().Ttl
		}
	}
	return time.Duration(minTTL) * time.Second
}

func handleRequest(w dns.ResponseWriter, r *dns.Msg) {
	key := cacheKey(r)
	if key == "" {
		dns.HandleFailed(w, r)
		return
	}

	cache.mu.RLock()
	entry, ok := cache.cachedDomains[key]
	if ok && time.Now().Before(entry.ExpiresAt) {
		res := entry.msg.Copy()
		res.Id = r.Id
		cache.mu.RUnlock()
		w.WriteMsg(res)
		return
	}
	cache.mu.RUnlock()

	if isBlacklisted(r) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Rcode = dns.RcodeNameError
		w.WriteMsg(m)
		return
	}

	m, _, err := dnsClient.Exchange(r, "127.0.0.1:5553")
	if err != nil {
		dns.HandleFailed(w, r)
		return
	}

	w.WriteMsg(m)

	go func(msg *dns.Msg, k string) {
		ttl := getShortestTTL(msg)
		cache.mu.Lock()
		cache.cachedDomains[k] = CacheEntry{
			msg:       msg.Copy(),
			ExpiresAt: time.Now().Add(ttl),
		}
		cache.mu.Unlock()
	}(m, key)
}

func main() {
	fetchWordlists()
	loadBlacklistFile("blacklist.txt")

	server := &dns.Server{
		Addr: "127.0.0.1:53",
		Net:  "udp",
	}

	dns.HandleFunc(".", handleRequest)

	fmt.Println("DNS Server running on 127.0.0.1:53")
	err := server.ListenAndServe()
	if err != nil {
		panic(err)
	}
}
