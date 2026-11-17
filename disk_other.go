//go:build !(linux || darwin || freebsd)

package main

func diskFree(path string) (total, free int64, ok bool) { return 0, 0, false }
