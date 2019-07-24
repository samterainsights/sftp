package sftp

import (
	"io"
	"os"
	"syscall"
)

// Error types that match the SFTP's SSH_FXP_STATUS codes. Gives you more
// direct control of the errors being sent vs. letting the library work them
// out from the standard os/io errors.

type fxerr uint32

const (
	ErrSshFxOk               = fxerr(ssh_FX_OK)
	ErrSshFxEof              = fxerr(ssh_FX_EOF)
	ErrSshFxNoSuchFile       = fxerr(ssh_FX_NO_SUCH_FILE)
	ErrSshFxPermissionDenied = fxerr(ssh_FX_PERMISSION_DENIED)
	ErrSshFxFailure          = fxerr(ssh_FX_FAILURE)
	ErrSshFxBadMessage       = fxerr(ssh_FX_BAD_MESSAGE)
	ErrSshFxNoConnection     = fxerr(ssh_FX_NO_CONNECTION)
	ErrSshFxConnectionLost   = fxerr(ssh_FX_CONNECTION_LOST)
	ErrSshFxOpUnsupported    = fxerr(ssh_FX_OP_UNSUPPORTED)
)

func (e fxerr) Error() string {
	switch e {
	case ErrSshFxOk:
		return "OK"
	case ErrSshFxEof:
		return "EOF"
	case ErrSshFxNoSuchFile:
		return "No Such File"
	case ErrSshFxPermissionDenied:
		return "Permission Denied"
	case ErrSshFxBadMessage:
		return "Bad Message"
	case ErrSshFxNoConnection:
		return "No Connection"
	case ErrSshFxConnectionLost:
		return "Connection Lost"
	case ErrSshFxOpUnsupported:
		return "Operation Unsupported"
	default:
		return "Failure"
	}
}

// translateErrno translates a syscall error number to a SFTP error code.
func translateErrno(errno syscall.Errno) uint32 {
	switch errno {
	case 0:
		return ssh_FX_OK
	case syscall.ENOENT:
		return ssh_FX_NO_SUCH_FILE
	case syscall.EPERM:
		return ssh_FX_PERMISSION_DENIED
	}

	return ssh_FX_FAILURE
}

func statusFromError(p ider, err error) *fxpStatusPkt {
	ret := &fxpStatusPkt{
		ID: p.id(),
		StatusError: StatusError{
			// ssh_FX_OK                = 0
			// ssh_FX_EOF               = 1
			// ssh_FX_NO_SUCH_FILE      = 2 ENOENT
			// ssh_FX_PERMISSION_DENIED = 3
			// ssh_FX_FAILURE           = 4
			// ssh_FX_BAD_MESSAGE       = 5
			// ssh_FX_NO_CONNECTION     = 6
			// ssh_FX_CONNECTION_LOST   = 7
			// ssh_FX_OP_UNSUPPORTED    = 8
			Code: ssh_FX_OK,
		},
	}
	if err == nil {
		return ret
	}

	debug("statusFromError: error is %T %#v", err, err)
	ret.StatusError.Code = ssh_FX_FAILURE
	ret.StatusError.msg = err.Error()

	switch e := err.(type) {
	case syscall.Errno:
		ret.StatusError.Code = translateErrno(e)
	case *os.PathError:
		debug("statusFromError,pathError: error is %T %#v", e.Err, e.Err)
		if errno, ok := e.Err.(syscall.Errno); ok {
			ret.StatusError.Code = translateErrno(errno)
		}
	case fxerr:
		ret.StatusError.Code = uint32(e)
	default:
		switch e {
		case io.EOF:
			ret.StatusError.Code = ssh_FX_EOF
		case os.ErrNotExist:
			ret.StatusError.Code = ssh_FX_NO_SUCH_FILE
		}
	}

	return ret
}
