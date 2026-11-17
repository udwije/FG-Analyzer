package main

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// v5.18.1: "$1 - interval '15 minutes'" made PostgreSQL guess $1 was an interval, so every WAN query failed with
// "operator does not exist: timestamp with time zone >= interval". A query parameter next to an interval must carry
// its type ($1::timestamptz).
func TestNoUntypedParameterIntervalArithmetic(t *testing.T) {
	re := regexp.MustCompile(`\$\d+\s*[-+]\s*(interval|make_interval)`)
	files, _ := filepath.Glob("*.go")
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if m := re.Find(b); m != nil && f != "sqlparam_test.go" {
			t.Errorf("%s: %q needs a cast, e.g. $1::timestamptz - interval", f, m)
		}
	}
}
