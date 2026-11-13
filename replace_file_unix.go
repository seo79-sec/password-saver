//go:build !windows

package main

import "os"

func replaceFile(source, destination string) error {
	return os.Rename(source, destination)
}

// replaceFileNoReplace atomically creates destination only if it does not
// already exist. source and destination must be in the same directory.
func replaceFileNoReplace(source, destination string) error {
	return os.Link(source, destination)
}

func syncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	if err := dir.Sync(); err != nil {
		_ = dir.Close()
		return err
	}
	return dir.Close()
}
