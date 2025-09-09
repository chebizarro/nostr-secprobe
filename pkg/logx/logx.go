package logx

import (
	"fmt"
	"log"
	"os"
	"strings"
)

var level = 1 // 0=debug,1=info,2=warn,3=error

func SetLevel(l string) {
	switch strings.ToLower(l) {
	case "debug": level = 0
	case "info": level = 1
	case "warn": level = 2
	case "error": level = 3
	}
}

func Debugf(f string, a ...any) { if level <= 0 { log.Printf("DEBUG "+f, a...) } }
func Infof(f string, a ...any)  { if level <= 1 { log.Printf("INFO  "+f, a...) } }
func Warnf(f string, a ...any)  { if level <= 2 { log.Printf("WARN  "+f, a...) } }
func Errorf(f string, a ...any) { if level <= 3 { log.Printf("ERROR "+f, a...) } }

func Fatalf(f string, a ...any) { Errorf(f, a...); os.Exit(1) }

func SprintKV(kv map[string]any) string {
	var b strings.Builder
	first := true
	for k, v := range kv {
		if !first { b.WriteString(" ") } else { first = false }
		b.WriteString(fmt.Sprintf("%s=%v", k, v))
	}
	return b.String()
}
