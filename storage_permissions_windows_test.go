//go:build windows

package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"unsafe"

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
			dacl, _, err := sd.DACL()
			if err != nil || dacl == nil || dacl.AceCount != 3 {
				t.Fatalf("expected exactly three explicit access grants: %v; %s", err, sd.String())
			}
			// Windows may serialize the current user's SID as an SDDL alias
			// (for example LA on the CI worker). Compare SID values, not SDDL.
			system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
			if err != nil {
				t.Fatal(err)
			}
			admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
			if err != nil {
				t.Fatal(err)
			}
			expected := []*windows.SID{user.User.Sid, system, admins}
			seen := make([]bool, len(expected))
			flags := uint8(0)
			if directory {
				flags = windows.OBJECT_INHERIT_ACE | windows.CONTAINER_INHERIT_ACE
			}
			// FILE_ALL_ACCESS is all file-specific rights plus standard rights
			// and SYNCHRONIZE, as defined by Windows winnt.h.
			const fileAllAccess = windows.STANDARD_RIGHTS_REQUIRED | windows.SYNCHRONIZE | 0x1ff
			for i := uint32(0); i < uint32(dacl.AceCount); i++ {
				var ace *windows.ACCESS_ALLOWED_ACE
				if err := windows.GetAce(dacl, i, &ace); err != nil {
					t.Fatal(err)
				}
				if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags != flags || ace.Mask != fileAllAccess {
					t.Fatalf("unexpected ACE type, inheritance or permissions: %+v", ace)
				}
				// SidStart is the first DWORD of the variable-length SID owned
				// by the security descriptor returned by Windows GetAce.
				trustee := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
				matched := false
				for j, sid := range expected {
					if trustee.Equals(sid) && !seen[j] {
						seen[j], matched = true, true
						break
					}
				}
				if !matched {
					t.Fatalf("unexpected or duplicate trustee: %s", trustee.String())
				}
			}
			runtime.KeepAlive(sd)
		})
	}
}
