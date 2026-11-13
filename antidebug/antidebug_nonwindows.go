//go:build !windows

package antidebug

// Check has no platform debugger probe outside Windows.
func Check() bool { return false }
