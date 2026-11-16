//go:build windows

package main

import "golang.org/x/sys/windows"

func storagePathIsReparsePoint(path string) (bool, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return false, err
	}
	attributes, err := windows.GetFileAttributes(name)
	if err != nil {
		return false, err
	}
	return attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0, nil
}

func renameStorageDirectoryNoReplace(source, destination string) error {
	from, err := windows.UTF16PtrFromString(source)
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(destination)
	if err != nil {
		return err
	}
	// Omitting MOVEFILE_REPLACE_EXISTING is atomic no-replace. WRITE_THROUGH
	// asks Windows to flush the move before returning.
	return windows.MoveFileEx(from, to, windows.MOVEFILE_WRITE_THROUGH)
}
