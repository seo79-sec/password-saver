//go:build windows

package main

import "golang.org/x/sys/windows"

func storageUserSecurityDescriptor(inheritable bool) (*windows.SECURITY_DESCRIPTOR, *windows.SID, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		return nil, nil, windows.ERROR_ACCESS_DENIED
	}
	sid := user.User.Sid
	inherit := ""
	if inheritable {
		inherit = "OICI"
	}
	// ACE flags are a separate SDDL field, including when they are empty.
	sddl := "O:" + sid.String() + "D:P(A;" + inherit + ";FA;;;" + sid.String() + ")(A;" + inherit + ";FA;;;SY)(A;" + inherit + ";FA;;;BA)"
	descriptor, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return nil, nil, err
	}
	return descriptor, sid, nil
}

func applyStorageSecurity(path string, inheritable bool) error {
	descriptor, owner, err := storageUserSecurityDescriptor(inheritable)
	if err != nil {
		return err
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		owner,
		nil,
		dacl,
		nil,
	)
}

func secureStorageDirectory(path string) error { return applyStorageSecurity(path, true) }
func secureStorageFile(path string) error      { return applyStorageSecurity(path, false) }
