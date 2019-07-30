package sftp

import (
	"fmt"
	"io"
	"os"
	"syscall"
)

// Error types that match the SFTP's SSH_FXP_STATUS codes. Gives you more
// direct control of the errors being sent vs. letting the library work them
// out from the standard os/io errors.

// Status codes
const (
	fxOK               = 0
	fxEOF              = 1
	fxNoSuchFile       = 2
	fxPermissionDenied = 3
	fxFailure          = 4
	fxBadMessage       = 5
	fxNoConnection     = 6 // client-generated only
	fxConnectionLost   = 7 // client-generated only
	fxOpUnsupported    = 8

	// Newer error codes
	// https://tools.ietf.org/html/draft-ietf-secsh-filexfer-13#section-9.1
	fxInvalidHandle           = 9
	fxNoSuchPath              = 10 // I think this is identical to SSH_FX_NO_SUCH_FILE but also can mean "invalid path"
	fxFileAlreadyExists       = 11
	fxWriteProtected          = 12
	fxNoMedia                 = 13
	fxNoSpaceOnFilesystem     = 14
	fxQuotaExceeded           = 15
	fxUnknownPrincipal        = 16
	fxLockConflict            = 17
	fxDirNotEmpty             = 18
	fxNotADirectory           = 19
	fxInvalidFilename         = 20
	fxLinkLoop                = 21
	fxCannotDelete            = 22
	fxInvalidParam            = 23
	fxIsADirectory            = 24
	fxByteRangeLockConflict   = 25
	fxByteRangeLockRefused    = 26
	fxDeletePending           = 27
	fxFileCorrupt             = 28
	fxOwnerInvalid            = 29
	fxGroupInvalid            = 30
	fxNoMatchingByteRangeLock = 31
)

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

	// ErrNotADirectory indicates that the given path exists but is not a
	// directory when a directory is required; directly translates to
	// SSH_FX_NOT_A_DIRECTORY.
	ErrNotADirectory = fxerr(fxNotADirectory)

	// ErrIsADirectory indicates that the given path exists but is a directory
	// in a context where a directory cannot be used; directly translates to
	// SSH_FX_FILE_IS_A_DIRECTORY.
	ErrIsADirectory = fxerr(fxIsADirectory)

	// ErrWriteProtected indicates that the file may not be written to for some
	// reason, e.g., it is on read-only media; directly translates to
	// SSH_FX_WRITE_PROTECT.
	ErrWriteProtected = fxerr(fxWriteProtected)
)

func (e fxerr) Error() string {
	switch e {
	case fxOK:
		return "No Error Occurred"
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
	case ErrNotADirectory:
		return "Not a Directory"
	case ErrIsADirectory:
		return "Is a Directory"
	default:
		return "Failure"
	}
}

// WithMessage wraps the error code in a *Status with the given message
// and "en" (English) as the language tag.
func (e fxerr) WithMessage(msg string) error {
	return &Status{uint32(e), msg, "en"}
}

// WithMessagef is identical to WithMessage but takes a format string with
// arguments.
func (e fxerr) WithMessagef(format string, args ...interface{}) error {
	return e.WithMessage(fmt.Sprintf(format, args...))
}

// A Status is an SFTP-defined type for conveying errors as well as success replies
// with no data. Status is exported so RequestHandler implementations may use it
// for more complete control over what gets sent back to the client.
//
// https://tools.ietf.org/pdf/draft-ietf-secsh-filexfer-02.pdf#38
type Status struct {
	Code uint32 // Status code
	Msg  string // Optional message with more details
	Lang string // Optional ISO 639 language tag for Msg
}

func (s *Status) Error() string {
	if s.Msg == "" {
		return fmt.Sprintf("sftp: %s", fxerr(s.Code))
	}
	return fmt.Sprintf("sftp: %s (%s)", fxerr(s.Code), s.Msg)
}

// translateErrno translates a syscall error number to an SFTP error code.
func translateErrno(errno syscall.Errno) uint32 {
	switch errno {
	case 0:
		return fxOK
	case syscall.ENOENT:
		return fxNoSuchFile
	case syscall.EPERM:
		return fxPermissionDenied
	case syscall.ENOTDIR:
		return fxNotADirectory
	case syscall.ENOTEMPTY:
		return fxDirNotEmpty
		// TODO(samterainsights): there are definitely more 1-to-1 mappings we can include
	}

	return fxFailure
}

func statusFromError(p ider, err error) *fxpStatusPkt {
	if status, ok := err.(*Status); ok {
		return &fxpStatusPkt{p.id(), *status}
	}

	ret := &fxpStatusPkt{
		ID: p.id(),
		Status: Status{
			Code: fxOK,
		},
	}
	if err == nil {
		return ret
	}

	debug("statusFromError[type=%T val=%#v msg=%q]", err, err, err.Error())
	ret.Status.Code = fxFailure
	ret.Status.Msg = err.Error()

	switch e := err.(type) {
	case syscall.Errno:
		ret.Status.Code = translateErrno(e)
	case *os.PathError:
		if errno, ok := e.Err.(syscall.Errno); ok {
			ret.Status.Code = translateErrno(errno)
		}
	case fxerr:
		ret.Status.Code = uint32(e)
	default:
		switch e {
		case io.EOF:
			ret.Status.Code = fxEOF
		case os.ErrNotExist:
			ret.Status.Code = fxNoSuchFile
		}
	}

	return ret
}
