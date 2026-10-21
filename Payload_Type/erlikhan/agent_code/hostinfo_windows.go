//go:build windows

package main

import "syscall"

func windowsTickCount() (uint64, error) {
	r1, _, err := syscall.NewLazyDLL("kernel32.dll").NewProc("GetTickCount64").Call()
	if r1 == 0 && err != nil {
		if errno, ok := err.(syscall.Errno); ok && errno != 0 {
			return 0, errno
		}
	}
	return uint64(r1), nil
}
