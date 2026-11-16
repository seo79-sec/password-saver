//go:build !windows

package main

import "os"

func secureStorageDirectory(path string) error { return os.Chmod(path, 0700) }
func secureStorageFile(path string) error      { return os.Chmod(path, 0600) }
