// Package relay contains active and passive probes for Nostr relay endpoints.
//
// It drives publish/subscribe workflows, validation checks (e.g., duplicate
// ID replay, signature rejection), malformed/policy tests, and burst/latency
// measurements. Options include concurrency and simple backoff controls.
package relay
