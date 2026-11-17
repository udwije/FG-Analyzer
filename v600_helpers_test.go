package main

import (
	"net/netip"
	"os"
)

func osMkdirAll(p string) error { return os.MkdirAll(p, 0755) }

func netipMust(s string) netip.Prefix { return netip.MustParsePrefix(s) }
