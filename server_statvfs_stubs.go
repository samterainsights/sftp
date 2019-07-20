// +build !darwin,!linux

package sftp

import (
	"syscall"
)

func (p fxpExtStatVFSPkt) respond(svr *Server) responsePacket {
	return statusFromError(p, syscall.ENOTSUP)
}
