package report

import (
	"fmt"
	"html"
	"encoding/json"
	"strings"
)

func RenderHTML(r *Results) string {
	var b strings.Builder
	b.WriteString("<!doctype html><html><head><meta charset=\"utf-8\"><meta name=\"color-scheme\" content=\"light dark\"><title>nostr-secprobe report</title>")
	b.WriteString(`<style>
body{font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;margin:24px;background:#ffffff;color:#111}
.h{font-weight:700;margin:0 0 8px 0}
.card{border:1px solid #eee;border-radius:8px;padding:12px;margin:12px 0;background:#fff}
.badge{display:inline-block;padding:2px 8px;border-radius:999px;font-size:12px;margin-left:8px}
.pass{background:#e6ffed;color:#006644}
.fail{background:#ffebe6;color:#bf2600}
.inc{background:#e6f7ff;color:#0747a6}
.sev-low{background:#eef6ff;color:#0747a6}
.sev-med{background:#fff7e6;color:#a36e00}
.sev-high{background:#ffe6e6;color:#bf2600}
.sev-crit{background:#000;color:#fff}
.active{background:#f0f5ff;color:#2f54eb}
.section{margin-top:16px;padding-top:8px;border-top:1px solid #f0f0f0}
@media (prefers-color-scheme: dark){
  body{background:#0b0b0b;color:#e6e6e6}
  .card{border-color:#2a2a2a;background:#121212}
  .section{border-top-color:#1a1a1a}
  .pass{background:#003d1f;color:#8dffb3}
  .fail{background:#3d0000;color:#ffb3b3}
  .inc{background:#002b4d;color:#8dccff}
  .sev-low{background:#0b2540;color:#8dccff}
  .sev-med{background:#402a00;color:#ffd58a}
  .sev-high{background:#401010;color:#ffb3b3}
  .sev-crit{background:#000;color:#fff}
  .active{background:#001a66;color:#99b3ff}
  .status-pass{background-color:#003d1f}
  .status-fail{background-color:#3d0000}
  .status-inc{background-color:#002b4d}
}
@media print{
  body{margin:8mm}
  .card{page-break-inside:avoid}
}
</style>`)
	b.WriteString("</head><body>")
    // Controls
    b.WriteString(`<div style="margin:8px 0;display:flex;gap:16px;align-items:center">
      <label style="cursor:pointer">
        <input id="toggle-inc" type="checkbox" checked>
        Hide INCONCLUSIVE
      </label>
      <label style="cursor:pointer">
        <input id="toggle-pass" type="checkbox">
        Hide PASS
      </label>
    </div>
    <script>
    (function(){
      function apply(){
        var hideInc = document.getElementById('toggle-inc').checked;
        var hidePass = document.getElementById('toggle-pass').checked;
        var incs = document.querySelectorAll('.status-inc');
        for (var i=0;i<incs.length;i++){ incs[i].style.display = hideInc ? 'none' : ''; }
        var passes = document.querySelectorAll('.status-pass');
        for (var j=0;j<passes.length;j++){ passes[j].style.display = hidePass ? 'none' : ''; }
      }
      document.addEventListener('DOMContentLoaded', apply);
      document.getElementById('toggle-inc').addEventListener('change', apply);
      document.getElementById('toggle-pass').addEventListener('change', apply);
    })();
    </script>`)
	b.WriteString(fmt.Sprintf("<h1 class=\"h\">nostr-secprobe report<span class=\"badge\">%s</span></h1>", html.EscapeString(r.TargetType)))
	if len(r.Targets) > 0 { b.WriteString("<div>Targets: "+html.EscapeString(strings.Join(r.Targets, ", "))+"</div>") }
	b.WriteString(fmt.Sprintf("<div>Generated: %s</div>", r.GeneratedAt.Format(timeLayout)))

    // Summary table per relay: counts of PASS/FAIL/INCONCLUSIVE and overall banner
    type agg struct{ pass, fail, inc int }
    sums := map[string]*agg{}
    overall := agg{}
    for _, f := range r.Findings {
        key := "General"
        if m, ok := f.Evidence.(map[string]any); ok {
            if rv, ok2 := m["relay"].(string); ok2 && rv != "" { key = rv }
        }
        if sums[key] == nil { sums[key] = &agg{} }
        switch f.Status {
        case Pass: sums[key].pass++; overall.pass++
        case Fail: sums[key].fail++; overall.fail++
        default: sums[key].inc++; overall.inc++
        }
    }
    // Overall banner
    b.WriteString(fmt.Sprintf("<div class=\"section\"><div class=\"h\">Overall: <span class=\"badge pass\">PASS %d</span> <span class=\"badge fail\">FAIL %d</span> <span class=\"badge inc\">INC %d</span></div></div>", overall.pass, overall.fail, overall.inc))
    if len(sums) > 0 {
        b.WriteString("<div class=section><div class=h>Summary</div><table style=\"border-collapse:collapse;width:100%;font-size:14px\">")
        b.WriteString("<thead><tr><th style=\"text-align:left;border-bottom:1px solid #ddd\">Relay</th><th style=\"text-align:right;border-bottom:1px solid #ddd\">PASS</th><th style=\"text-align:right;border-bottom:1px solid #ddd\">FAIL</th><th style=\"text-align:right;border-bottom:1px solid #ddd\">INCONCLUSIVE</th></tr></thead><tbody>")
        // Render in the order: general, targets, then others
        var order []string
        seen := map[string]bool{}
        if _, ok := sums["General"]; ok { order = append(order, "General"); seen["General"] = true }
        for _, t := range r.Targets { if _, ok := sums[t]; ok && !seen[t] { order = append(order, t); seen[t] = true } }
        for k := range sums { if !seen[k] { order = append(order, k); seen[k] = true } }
        for _, k := range order {
            a := sums[k]
            b.WriteString(fmt.Sprintf("<tr><td style=\"padding:6px 4px\">%s</td><td style=\"padding:6px 4px;text-align:right\">%d</td><td style=\"padding:6px 4px;text-align:right\">%d</td><td style=\"padding:6px 4px;text-align:right\">%d</td></tr>", html.EscapeString(k), a.pass, a.fail, a.inc))
        }
        b.WriteString("</tbody></table></div>")
    }

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
			// Title with status badge, severity badge, and Active badge if applicable
			sevCl := "sev-low"
			switch f.Severity {
			case Medium: sevCl = "sev-med"
			case High: sevCl = "sev-high"
			case Critical: sevCl = "sev-crit"
			}
			b.WriteString("<div class=h>")
			b.WriteString(html.EscapeString(f.Name))
			b.WriteString(fmt.Sprintf(" <span class=\"badge %s\">%s</span>", cl, f.Status))
			b.WriteString(fmt.Sprintf(" <span class=\"badge %s\">%s</span>", sevCl, f.Severity))
			if f.Active { b.WriteString(" <span class=\"badge active\">ACTIVE</span>") }
			b.WriteString("</div>")
			b.WriteString(fmt.Sprintf("<div>Category: %s</div>", html.EscapeString(f.Category)))
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
