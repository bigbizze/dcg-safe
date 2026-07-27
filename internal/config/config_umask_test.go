//go:build linux || darwin

package config

import "golang.org/x/sys/unix"

func init() {
	umask = unix.Umask
}
