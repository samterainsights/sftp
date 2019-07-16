// +build darwin dragonfly freebsd !android,linux netbsd openbsd solaris aix
// +build cgo

package sftp

import (
	"os"
	"syscall"
)

func fileStatFromInfoOs(fi os.FileInfo, flags *uint32, fileStat *FileStat) {
	if statt, ok := fi.Sys().(*syscall.Stat_t); ok {
		*flags |= sftpAttrFlagUIDGID
		fileStat.UID = statt.Uid
		fileStat.GID = statt.Gid
	}
}
