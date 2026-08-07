package report

import pkgreport "git.sharegap.net/cascadia/nostr-secprobe/pkg/report"

type Severity = pkgreport.Severity
type Status = pkgreport.Status
type Finding = pkgreport.Finding
type Results = pkgreport.Results

const (
	Low          = pkgreport.Low
	Medium       = pkgreport.Medium
	High         = pkgreport.High
	Critical     = pkgreport.Critical
	Pass         = pkgreport.Pass
	Fail         = pkgreport.Fail
	Inconclusive = pkgreport.Inconclusive
)
