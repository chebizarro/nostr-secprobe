package report

import (
	"fmt"
	"strings"
	"encoding/json"

	"github.com/go-pdf/fpdf"
)

// RenderPDFToFile renders a minimal PDF from the results. It is not a pixel-perfect HTML render
// but provides a cross-platform, CGO-free PDF artifact.
func RenderPDFToFile(r *Results, path string) error {
	pdf := fpdf.New("P", "mm", "A4", "")
	pdf.SetTitle("nostr-secprobe report", false)
	pdf.AddPage()
	pdf.SetFont("Arial", "B", 16)
	pdf.Cell(0, 10, "nostr-secprobe report")
	pdf.Ln(10)
	pdf.SetFont("Arial", "", 12)
	pdf.Cell(0, 8, fmt.Sprintf("Target: %s", r.TargetType))
	pdf.Ln(8)
	if len(r.Targets) > 0 {
		pdf.Cell(0, 8, fmt.Sprintf("Targets: %s", strings.Join(r.Targets, ", ")))
		pdf.Ln(8)
	}
	for _, f := range r.Findings {
		pdf.SetFont("Arial", "B", 12)
		pdf.MultiCell(0, 6, fmt.Sprintf("%s [%s]", f.Name, f.Status), "", "L", false)
		pdf.SetFont("Arial", "", 11)
		pdf.MultiCell(0, 5, fmt.Sprintf("Category: %s  Severity: %s", f.Category, f.Severity), "", "L", false)
		if f.Evidence != nil {
			pdf.SetFont("Courier", "", 9)
			pdf.MultiCell(0, 4, string(mustJSON(f.Evidence)), "", "L", false)
		}
		if len(f.Mitigations) > 0 {
			pdf.SetFont("Arial", "I", 10)
			for _, m := range f.Mitigations {
				pdf.MultiCell(0, 4, "- "+m, "", "L", false)
			}
		}
		pdf.Ln(2)
	}
	return pdf.OutputFileAndClose(path)
}

func mustJSON(v any) []byte {
	b, _ := json.MarshalIndent(v, "", "  ")
	return b
}
