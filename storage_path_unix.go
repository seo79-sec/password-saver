//go:build !windows

package main

func storagePathIsReparsePoint(string) (bool, error) { return false, nil }
