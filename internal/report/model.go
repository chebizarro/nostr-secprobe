package report

import "time"

type Severity string
const (
	Low Severity = "LOW"
	Medium Severity = "MEDIUM"
	High Severity = "HIGH"
	Critical Severity = "CRITICAL"
)

type Status string
const (
	Pass Status = "PASS"
	Fail Status = "FAIL"
	Inconclusive Status = "INCONCLUSIVE"
)

type Finding struct {
	Name      string      `json:"name"`
	Category  string      `json:"category"`
	Severity  Severity    `json:"severity"`
	Status    Status      `json:"status"`
	Evidence  interface{} `json:"evidence,omitempty"`
	Mitigations []string  `json:"mitigations,omitempty"`
	Timestamp time.Time   `json:"timestamp"`
}

type Results struct {
	TargetType string     `json:"target_type"`
	Targets    []string   `json:"targets,omitempty"`
	Findings   []Finding  `json:"findings"`
	PubKey     string     `json:"pubkey,omitempty"`
	Notes      []string   `json:"notes,omitempty"`
	GeneratedAt time.Time `json:"generated_at"`
}

func (r *Results) Add(f Finding) { r.Findings = append(r.Findings, f) }
func (r *Results) HasFindings() bool {
	for _, f := range r.Findings {
		if f.Status == Fail { return true }
		if f.Severity == High || f.Severity == Critical {
			if f.Status != Pass { return true }
		}
	}
	return false
}
