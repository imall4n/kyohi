package main

import (
	"fmt"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type CacheEntry struct {
	msg       *dns.Msg
	ExpiresAt time.Time
}

type Cache struct {
	cachedDomains map[string]CacheEntry
	mu            sync.RWMutex
}

func cacheKey(r *dns.Msg) string {
	requestDetails := r.Question[0]
	requestedDomain := requestDetails.Name

	return requestedDomain + ":" + dns.TypeToString[requestDetails.Qtype]
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

	cache.mu.Lock()

	entry, ok := cache.cachedDomains[key]

	if ok && time.Now().Before(entry.ExpiresAt) {
		res := entry.msg.Copy()
		res.Id = r.Id
		w.WriteMsg(res)
		cache.mu.Unlock()
		return
	}

	cache.mu.Unlock()

	fmt.Println(key)

	c := new(dns.Client)
	res, _, err := c.Exchange(r, "1.1.1.1:53")

	if err != nil {
		dns.HandleFailed(w, r)
		return
	}

	ttl := getShortestTTL(res)

	cache.mu.Lock()
	cache.cachedDomains[key] = CacheEntry{
		msg:       res.Copy(),
		ExpiresAt: time.Now().Add(ttl),
	}
	cache.mu.Unlock()

	w.WriteMsg(res)
}

func main() {
	server := &dns.Server{Addr: "127.0.0.1:53", Net: "udp"}
	dns.HandleFunc(".", handleRequest)

	err := server.ListenAndServe()

	if err != nil {
		panic(err)
	}
}
