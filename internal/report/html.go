package report

import (
	"fmt"
	"html"
	"encoding/json"
	"strings"
)

func RenderHTML(r *Results) string {
	var b strings.Builder
	b.WriteString("<!doctype html><html><head><meta charset=\"utf-8\"><title>nostr-secprobe report</title>")
	b.WriteString(`<style>
body{font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;margin:24px;}
.h{font-weight:700;margin:0 0 8px 0}
.card{border:1px solid #eee;border-radius:8px;padding:12px;margin:12px 0}
.badge{display:inline-block;padding:2px 8px;border-radius:999px;font-size:12px;margin-left:8px}
.pass{background:#e6ffed;color:#006644}
.fail{background:#ffebe6;color:#bf2600}
.inc{background:#e6f7ff;color:#0747a6}
.section{margin-top:16px;padding-top:8px;border-top:1px solid #f0f0f0}
</style>`)
	b.WriteString("</head><body>")
	b.WriteString(fmt.Sprintf("<h1 class=\"h\">nostr-secprobe report<span class=\"badge\">%s</span></h1>", html.EscapeString(r.TargetType)))
	if len(r.Targets) > 0 { b.WriteString("<div>Targets: "+html.EscapeString(strings.Join(r.Targets, ", "))+"</div>") }
	b.WriteString(fmt.Sprintf("<div>Generated: %s</div>", r.GeneratedAt.Format(timeLayout)))

	// Group findings by relay when available in evidence; fall back to "general".
	groups := map[string][]Finding{}
	for _, f := range r.Findings {
		key := "general"
		if m, ok := f.Evidence.(map[string]any); ok {
			if rv, ok2 := m["relay"].(string); ok2 && rv != "" {
				key = rv
			}
		}
		groups[key] = append(groups[key], f)
	}
	// Maintain display order: general first, then each target in order, then any other keys.
	var order []string
	seen := map[string]bool{}
	if _, ok := groups["general"]; ok { order = append(order, "general"); seen["general"] = true }
	for _, t := range r.Targets {
		if _, ok := groups[t]; ok && !seen[t] { order = append(order, t); seen[t] = true }
	}
	for k := range groups {
		if !seen[k] { order = append(order, k); seen[k] = true }
	}
	for _, k := range order {
		title := k
		if k == "general" { title = "General" }
		b.WriteString(fmt.Sprintf("<h2 class=\"h section\">%s</h2>", html.EscapeString(title)))
		for _, f := range groups[k] {
			cl := "inc"
			if f.Status == Pass { cl = "pass" } else if f.Status == Fail { cl = "fail" }
			b.WriteString("<div class=card>")
			b.WriteString(fmt.Sprintf("<div class=h>%s <span class=\"badge %s\">%s</span></div>", html.EscapeString(f.Name), cl, f.Status))
			b.WriteString(fmt.Sprintf("<div>Category: %s | Severity: %s</div>", html.EscapeString(f.Category), f.Severity))
			if f.Evidence != nil {
				b.WriteString("<pre style=\"white-space:pre-wrap\">")
				b.WriteString(html.EscapeString(asJSON(f.Evidence)))
				b.WriteString("</pre>")
			}
			if len(f.Mitigations) > 0 {
				b.WriteString("<ul>")
				for _, m := range f.Mitigations { b.WriteString("<li>"+html.EscapeString(m)+"</li>") }
				b.WriteString("</ul>")
			}
			b.WriteString("</div>")
		}
	}
	b.WriteString("</body></html>")
	return b.String()
}

const timeLayout = "2006-01-02 15:04:05 MST"

func asJSON(v any) string {
	bs, _ := json.MarshalIndent(v, "", "  ")
	return string(bs)
}
