package report

import (
	"encoding/json"
	"os"
)

func WriteJSONToFile(r *Results, path string) error {
	b, _ := json.MarshalIndent(r, "", "  ")
	return os.WriteFile(path, b, 0o644)
}

func MergeJSONFiles(paths []string) (*Results, error) {
	var out Results
	for i, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil { return nil, err }
		var r Results
		if err := json.Unmarshal(b, &r); err != nil { return nil, err }
		if i == 0 { out = r } else { out.Findings = append(out.Findings, r.Findings...) }
	}
	return &out, nil
}
