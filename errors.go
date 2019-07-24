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
	// ErrEOF indicates end-of-file; directly translates to SSH_FX_EOF.
	ErrEOF = fxerr(fxEOF)

	// ErrNoSuchFile means a reference was made to a path which does not exist;
	// directly translates to SSH_FX_NO_SUCH_FILE.
	ErrNoSuchFile = fxerr(fxNoSuchFile)

	// ErrPermDenied means the client does not have sufficient permissions to
	// perform the operation; directly translates to SSH_FX_PERMISSION_DENIED.
	ErrPermDenied = fxerr(fxPermissionDenied)

	// ErrGeneric indicates that some error occurred; directly translates to
	// SSH_FX_FAILURE. Use more specific errors when possible.
	ErrGeneric = fxerr(fxFailure)

	// ErrBadMessage means an incorrectly formatted packet or protocol
	// incompatibility was detected; directly translates to SSH_FX_BAD_MESSAGE.
	ErrBadMessage = fxerr(fxBadMessage)

	// ErrNoConnection is a client-generated pseudo-error indicating that it
	// has no connection to the server; directly translates to
	// SSH_FX_NO_CONNECTION.
	ErrNoConnection = fxerr(fxNoConnection)

	// ErrConnectionLost is a client-generated pseudo-error indicating that
	// connection to the server has been lost; directly translates to
	// SSH_FX_CONNECTION_LOST.
	ErrConnectionLost = fxerr(fxConnectionLost)

	// ErrOpUnsupported indicates that an operation is not implemented by the
	// server; directly translates to SSH_FX_OP_UNSUPPORTED.
	ErrOpUnsupported = fxerr(fxOpUnsupported)
)

func (e fxerr) Error() string {
	switch e {
	case ErrEOF:
		return "EOF"
	case ErrNoSuchFile:
		return "No Such File"
	case ErrPermDenied:
		return "Permission Denied"
	case ErrBadMessage:
		return "Bad Message"
	case ErrNoConnection:
		return "No Connection"
	case ErrConnectionLost:
		return "Connection Lost"
	case ErrOpUnsupported:
		return "Operation Unsupported"
	default:
		return "Failure"
	}
}

// translateErrno translates a syscall error number to a SFTP error code.
func translateErrno(errno syscall.Errno) uint32 {
	switch errno {
	case 0:
		return fxOK
	case syscall.ENOENT:
		return fxNoSuchFile
	case syscall.EPERM:
		return fxPermissionDenied
	}

	return fxFailure
}

func statusFromError(p ider, err error) *fxpStatusPkt {
	ret := &fxpStatusPkt{
		ID: p.id(),
		StatusError: StatusError{
			// fxOK                = 0
			// fxEOF               = 1
			// fxNoSuchFile      = 2 ENOENT
			// fxPermissionDenied = 3
			// fxFailure           = 4
			// fxBadMessage       = 5
			// fxNoConnection     = 6
			// fxConnectionLost   = 7
			// fxOpUnsupported    = 8
			Code: fxOK,
		},
	}
	if err == nil {
		return ret
	}

	debug("statusFromError: error is %T %#v", err, err)
	ret.StatusError.Code = fxFailure
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
			ret.StatusError.Code = fxEOF
		case os.ErrNotExist:
			ret.StatusError.Code = fxNoSuchFile
		}
	}

	return ret
}
