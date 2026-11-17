//go:build !windows

package main

import "errors"

func runService(*App) error    { return errors.New("Windows only") }
func isService() (bool, error) { return false, nil }
