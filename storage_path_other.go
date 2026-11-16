//go:build !windows && !linux

package main

import (
	"errors"
)

func renameStorageDirectoryNoReplace(string, string) error {
	return errors.New("atomic no-replace directory move is unsupported on this platform")
}
