package preview

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"
)

type logLine struct {
	Time   time.Time       `json:"time"`
	Path   string          `json:"path"`
	Query  string          `json:"query"`
	Header http.Header     `json:"header"`
}

var (
	mu    sync.Mutex
	seenT = map[string]bool{}
)

// Serve starts a minimal HTTP server that logs inbound requests as JSON lines.
func Serve(addr string) error {
	h := http.NewServeMux()
	// Query whether a token has been seen.
	h.HandleFunc("/_seen", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("token")
		mu.Lock()
		seen := seenT[q]
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]bool{"seen": seen})
	})
	h.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		ll := logLine{Time: time.Now().UTC(), Path: r.URL.Path, Query: r.URL.RawQuery, Header: r.Header}
		b, _ := json.Marshal(ll)
		fmt.Println(string(b))
		// Record token if present
		if t := r.URL.Query().Get("token"); t != "" {
			mu.Lock()
			seenT[t] = true
			mu.Unlock()
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok\n"))
	})
	log.Printf("preview-probe listening on %s", addr)
	return http.ListenAndServe(addr, h)
}
