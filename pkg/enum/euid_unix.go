//go:build aix || android || darwin || dragonfly || freebsd || illumos || ios || linux || netbsd || openbsd || solaris

package enum

import "os"

func currentEUID() int {
	return os.Geteuid()
}
