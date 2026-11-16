//go:build windows

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// A cross-build cannot detect malformed SDDL or SetNamedSecurityInfo failures.
// Run this on the Windows CI worker against synthetic temporary files.
func TestWindowsStorageACLForDirectoriesAndFiles(t *testing.T) {
	for _, directory := range []bool{false, true} {
		t.Run("ACL", func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "synthetic-vault")
			if directory {
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
				if err := secureStorageDirectory(path); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.WriteFile(path, []byte("synthetic ciphertext"), 0600); err != nil {
					t.Fatal(err)
				}
				if err := secureStorageFile(path); err != nil {
					t.Fatal(err)
				}
			}
			sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
			if err != nil || !sd.IsValid() {
				t.Fatalf("invalid ACL: %v", err)
			}
			control, _, err := sd.Control()
			if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
				t.Fatalf("DACL inherits unintended access: %v", err)
			}
			user, err := windows.GetCurrentProcessToken().GetTokenUser()
			if err != nil {
				t.Fatal(err)
			}
			owner, _, err := sd.Owner()
			if err != nil || !owner.Equals(user.User.Sid) {
				t.Fatalf("wrong owner: %v", err)
			}
			dacl := sd.String()
			flags := ""
			if directory {
				flags = "OICI"
			}
			for _, trustee := range []string{user.User.Sid.String(), "SY", "BA"} {
				if !strings.Contains(dacl, "(A;"+flags+";FA;;;"+trustee+")") {
					t.Fatalf("required ACE absent: %s", dacl)
				}
			}
			if strings.Count(dacl, "(A;") != 3 {
				t.Fatalf("unexpected access grant: %s", dacl)
			}
		})
	}
}
