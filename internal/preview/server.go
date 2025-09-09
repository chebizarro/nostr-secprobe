package preview

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
)

type logLine struct {
	Time   time.Time       `json:"time"`
	Path   string          `json:"path"`
	Query  string          `json:"query"`
	Header http.Header     `json:"header"`
}

// Serve starts a minimal HTTP server that logs inbound requests as JSON lines.
func Serve(addr string) error {
	h := http.NewServeMux()
	h.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		ll := logLine{Time: time.Now().UTC(), Path: r.URL.Path, Query: r.URL.RawQuery, Header: r.Header}
		b, _ := json.Marshal(ll)
		fmt.Println(string(b))
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok\n"))
	})
	log.Printf("preview-probe listening on %s", addr)
	return http.ListenAndServe(addr, h)
}
