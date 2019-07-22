// +build darwin linux

// fill in statvfs structure with OS specific values
// Statfs_t is different per-kernel, and only exists on some unixes (not Solaris for instance)

package sftp

import (
	"syscall"
)

func (p *fxpExtStatvfsPkt) respond(svr *Server) responsePacket {
	stat := &syscall.Statfs_t{}
	if err := syscall.Statfs(p.Path, stat); err != nil {
		return statusFromError(p, err)
	}

	vfs, err := statvfsFromStatfst(stat)
	if err != nil {
		return statusFromError(p, err)
	}
	return &fxpExtVfsPkt{p.ID, *vfs}
}
