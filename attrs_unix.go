// +build darwin dragonfly freebsd !android,linux netbsd openbsd solaris aix
// +build cgo

package sftp

import (
	"os"
	"syscall"
)

func fileAttrFromInfoOS(fi os.FileInfo, attr *FileAttr) {
	if stat, ok := fi.Sys().(*syscall.Stat_t); ok {
		attr.Flags |= AttrFlagUIDGID
		attr.UID = stat.Uid
		attr.GID = stat.Gid
	}
}
