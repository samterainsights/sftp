// +build !darwin,!linux

package sftp

import (
	"syscall"
)

func (p fxpExtStatvfsPkt) respond(svr *Server) responsePacket {
	return statusFromError(p, syscall.ENOTSUP)
}
