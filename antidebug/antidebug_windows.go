//go:build windows

package antidebug

import (
	"syscall"
	"unsafe"
)

var (
	kernel32                = syscall.NewLazyDLL("kernel32.dll")
	procIsDebuggerPresent   = kernel32.NewProc("IsDebuggerPresent")
	procCheckRemoteDebugger = kernel32.NewProc("CheckRemoteDebuggerPresent")
)

// Check returns true if a debugger is detected on Windows
func Check() bool {
	// 1. Стандартная проверка флага BeingDebugged в PEB
	flag, _, _ := procIsDebuggerPresent.Call()
	if flag != 0 {
		return true
	}

	// 2. Проверка на наличие удаленного отладчика
	var isRemoteDebugged uint32
	currentProcess, _ := syscall.GetCurrentProcess()

	// Используем unsafe.Pointer для корректной передачи адреса переменной в Windows API
	_, _, _ = procCheckRemoteDebugger.Call(
		uintptr(currentProcess),
		uintptr(unsafe.Pointer(&isRemoteDebugged)),
	)

	return isRemoteDebugged != 0
}
