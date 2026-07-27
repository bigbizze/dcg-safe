//go:build linux || darwin

package install

import "golang.org/x/sys/unix"

func init() {
	installUmask = unix.Umask
}
