package main

import (
	"bufio"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/bits-and-blooms/bloom/v3"
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
	data map[string]CacheEntry
	mu   sync.RWMutex
}

const maxCacheEntries = 50000

var (
	dnsClient = &dns.Client{
		Net:     "udp",
		Timeout: 2 * time.Second,
	}

	blacklist *bloom.BloomFilter
	blMu      sync.Mutex

	cache = &Cache{
		data: make(map[string]CacheEntry),
	}
)

func loadBlacklist() {
	data, err := os.ReadFile("./config.yaml")
	if err != nil {
		log.Fatal(err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		log.Fatal(err)
	}

	estimated := uint(3_000_000)
	blacklist = bloom.NewWithEstimates(estimated, 0.001)

	var wg sync.WaitGroup

	for _, url := range cfg.Wordlists {
		wg.Add(1)
		go func(u string) {
			defer wg.Done()

			res, err := http.Get(u)
			if err != nil {
				return
			}
			defer res.Body.Close()

			scanner := bufio.NewScanner(res.Body)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}

				line = strings.TrimPrefix(line, "0.0.0.0 ")
				line = strings.TrimPrefix(line, "||")
				line = strings.TrimSuffix(line, "^")
				line = strings.TrimSuffix(line, ".")
				line = strings.ToLower(line)

				if line != "" {
					blMu.Lock()
					blacklist.AddString(line)
					blMu.Unlock()
				}
			}
		}(url)
	}

	wg.Wait()
}

func isBlacklisted(r *dns.Msg) bool {
	if len(r.Question) == 0 {
		return false
	}
	name := strings.TrimSuffix(r.Question[0].Name, ".")
	return blacklist.TestString(strings.ToLower(name))
}

func cacheKey(r *dns.Msg) string {
	if len(r.Question) == 0 {
		return ""
	}
	q := r.Question[0]
	return q.Name + ":" + dns.TypeToString[q.Qtype]
}

func getTTL(m *dns.Msg) time.Duration {
	if len(m.Answer) == 0 {
		return 30 * time.Second
	}
	min := uint32(3600)
	for _, rr := range m.Answer {
		if rr.Header().Ttl < min {
			min = rr.Header().Ttl
		}
	}
	return time.Duration(min) * time.Second
}

func handleRequest(w dns.ResponseWriter, r *dns.Msg) {
	key := cacheKey(r)
	if key == "" {
		dns.HandleFailed(w, r)
		return
	}

	cache.mu.RLock()
	if e, ok := cache.data[key]; ok && time.Now().Before(e.ExpiresAt) {
		res := e.msg.Copy()
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

	cache.mu.Lock()
	if len(cache.data) >= maxCacheEntries {
		cache.data = make(map[string]CacheEntry)
	}
	cache.data[key] = CacheEntry{
		msg:       m.Copy(),
		ExpiresAt: time.Now().Add(getTTL(m)),
	}
	cache.mu.Unlock()
}

func main() {
	loadBlacklist()

	dns.HandleFunc(".", handleRequest)

	server := &dns.Server{
		Addr: "127.0.0.1:53",
		Net:  "udp",
	}

	fmt.Println("DNS server listening on 127.0.0.1:53")
	if err := server.ListenAndServe(); err != nil {
		panic(err)
	}
}
