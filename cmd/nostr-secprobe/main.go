package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"nostr-secprobe/internal/preview"
	"nostr-secprobe/internal/probes/client"
	"nostr-secprobe/internal/probes/connect"
	"nostr-secprobe/internal/probes/relay"
	"nostr-secprobe/internal/report"
	"nostr-secprobe/pkg/logx"
)

var (
	flagTargets     string
	flagOut         string
	flagHTML        string
	flagPDF         string
	flagPreviewHost string
	flagActive      bool
	flagIUnderstand bool
	flagRate        int
	flagMaxEvents   int
	flagTimeout     time.Duration
	flagPubKey      string
	flagSecKey      string
	flagNoStore     bool
	flagLogLevel    string
	flagDryRun      bool
)

func main() {
	root := &cobra.Command{
		Use:   "nostr-secprobe",
		Short: "Probe Nostr relays and clients for known vulns",
	}

	root.PersistentFlags().StringVar(&flagTargets, "targets", env("NSEC_TARGETS", ""), "CSV of relay URLs or client targets")
	root.PersistentFlags().StringVar(&flagOut, "out", env("NSEC_OUT", "report.json"), "JSON report output path")
	root.PersistentFlags().StringVar(&flagHTML, "html", "", "HTML report output path")
	root.PersistentFlags().StringVar(&flagPDF, "pdf", "", "PDF report output path")
	root.PersistentFlags().StringVar(&flagPreviewHost, "preview-host", env("NSEC_PREVIEW_HOST", ""), "Preview probe host (http[s]://)")
	root.PersistentFlags().BoolVar(&flagActive, "active", false, "Enable intrusive tests")
	root.PersistentFlags().BoolVar(&flagIUnderstand, "i-understand", false, "Acknowledge legal scope for intrusive tests")
	root.PersistentFlags().IntVar(&flagRate, "rate", envInt("NSEC_RATE", 5), "Max events per second")
	root.PersistentFlags().IntVar(&flagMaxEvents, "max-events", envInt("NSEC_MAX_EVENTS", 100), "Max events to send")
	root.PersistentFlags().DurationVar(&flagTimeout, "timeout", envDuration("NSEC_TIMEOUT", time.Minute), "Global timeout")
	root.PersistentFlags().StringVar(&flagPubKey, "pubkey", env("NSEC_PUBKEY", ""), "Hex pubkey")
	root.PersistentFlags().StringVar(&flagSecKey, "seckey", env("NSEC_SECKEY", ""), "Hex seckey")
	root.PersistentFlags().BoolVar(&flagNoStore, "no-store", false, "Do not store ephemeral private key on disk")
	root.PersistentFlags().StringVar(&flagLogLevel, "log-level", "info", "log level: debug,info,warn,error")
	root.PersistentFlags().BoolVar(&flagDryRun, "dry-run", false, "Print actions without network mutation")

	root.AddCommand(cmdProbeRelay())
	root.AddCommand(cmdProbeClient())
	root.AddCommand(cmdProbeConnect())
	root.AddCommand(cmdServePreview())
	root.AddCommand(cmdReport())

	if err := root.Execute(); err != nil {
		if ee, ok := err.(exitError); ok {
			fmt.Fprintln(os.Stderr, ee.err)
			os.Exit(ee.code)
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(3)
	}
}

func cmdProbeRelay() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "probe relay",
		Short: "Probe relay URLs",
		RunE: func(cmd *cobra.Command, args []string) error {
			logx.SetLevel(flagLogLevel)
			if flagTargets == "" {
				return exitCodeErr(3, fmt.Errorf("--targets or NSEC_TARGETS required"))
			}
			targets := splitCSV(flagTargets)
			ctx, cancel := context.WithTimeout(cmd.Context(), flagTimeout)
			defer cancel()
			res, err := relay.Run(ctx, relay.Options{
				Targets:     targets,
				Rate:        flagRate,
				MaxEvents:   flagMaxEvents,
				DryRun:      flagDryRun,
				Active:      flagActive,
				IUnderstand: flagIUnderstand,
				PubKeyHex:   flagPubKey,
				SecKeyHex:   flagSecKey,
				NoStore:     flagNoStore,
			})
			if err != nil {
				return exitCodeErr(4, err)
			}
			return writeReports(res)
		},
	}
	return cmd
}

func cmdProbeClient() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "probe client",
		Short: "Probe a client harness",
		RunE: func(cmd *cobra.Command, args []string) error {
			logx.SetLevel(flagLogLevel)
			ctx, cancel := context.WithTimeout(cmd.Context(), flagTimeout)
			defer cancel()
			res, err := client.Run(ctx, client.Options{
				PreviewHost: flagPreviewHost,
				Active:      flagActive,
				IUnderstand: flagIUnderstand,
				DryRun:      flagDryRun,
			})
			if err != nil {
				return exitCodeErr(4, err)
			}
			return writeReports(res)
		},
	}
	return cmd
}

func cmdProbeConnect() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "probe connect",
		Short: "NIP-46 key-separation probe",
		RunE: func(cmd *cobra.Command, args []string) error {
			logx.SetLevel(flagLogLevel)
			ctx, cancel := context.WithTimeout(cmd.Context(), flagTimeout)
			defer cancel()
			res, err := connect.Run(ctx, connect.Options{DryRun: flagDryRun, Active: flagActive, IUnderstand: flagIUnderstand})
			if err != nil {
				return exitCodeErr(4, err)
			}
			return writeReports(res)
		},
	}
	return cmd
}

func cmdServePreview() *cobra.Command {
	var addr string
	cmd := &cobra.Command{
		Use:   "serve preview-probe",
		Short: "Start preview-probe HTTP server",
		RunE: func(cmd *cobra.Command, args []string) error {
			logx.SetLevel(flagLogLevel)
			return preview.Serve(addr)
		},
	}
	cmd.Flags().StringVar(&addr, "addr", ":8080", "listen address")
	return cmd
}

func cmdReport() *cobra.Command {
	var in []string
	cmd := &cobra.Command{
		Use:   "report",
		Short: "Convert/merge JSON to HTML/PDF",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(in) == 0 {
				return fmt.Errorf("provide at least one JSON via --in")
			}
			merged, err := report.MergeJSONFiles(in)
			if err != nil {
				return err
			}
			return writeReports(merged)
		},
	}
	cmd.Flags().StringSliceVar(&in, "in", nil, "input JSONs to merge")
	return cmd
}

func writeReports(res *report.Results) error {
	// Write JSON
	if flagOut != "" {
		b, _ := json.MarshalIndent(res, "", "  ")
		if err := os.WriteFile(flagOut, b, 0o644); err != nil {
			return err
		}
		logx.Infof("wrote JSON report: %s", flagOut)
	}
	if flagHTML != "" {
		html := report.RenderHTML(res)
		if err := os.WriteFile(flagHTML, []byte(html), 0o644); err != nil {
			return err
		}
		logx.Infof("wrote HTML report: %s", flagHTML)
	}
	if flagPDF != "" {
		if err := report.RenderPDFToFile(res, flagPDF); err != nil {
			logx.Warnf("PDF generation failed, wrote HTML if provided: %v", err)
			return nil
		}
		logx.Infof("wrote PDF report: %s", flagPDF)
	}
	if res.HasFindings() {
		return exitCodeErr(2, fmt.Errorf("findings present"))
	}
	return nil
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
func envInt(k string, def int) int {
	if v := os.Getenv(k); v != "" {
		var i int
		fmt.Sscanf(v, "%d", &i)
		return i
	}
	return def
}
func envDuration(k string, def time.Duration) time.Duration {
	if v := os.Getenv(k); v != "" {
		d, err := time.ParseDuration(v)
		if err == nil { return d }
	}
	return def
}

func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	var out []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" { out = append(out, p) }
	}
	return out
}

type exitError struct{ code int; err error }
func (e exitError) Error() string { return e.err.Error() }
func exitCodeErr(code int, err error) error { return exitError{code: code, err: err} }

func init() { cobra.MousetrapHelpText = "" }
