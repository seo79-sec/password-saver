//go:build windows

package main

import "golang.org/x/sys/windows"

func replaceFile(source, destination string) error {
	from, err := windows.UTF16PtrFromString(source)
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(destination)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(from, to, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}

// MoveFileEx with WRITE_THROUGH flushes the replacement on Windows; opening
// directories for fsync is unsupported by the Windows filesystem API.
func syncDirectory(string) error { return nil }
