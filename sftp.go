// Package sftp implements the SSH File Transfer Protocol as described in
// https://tools.ietf.org/html/draft-ietf-secsh-filexfer-02
package sftp

import (
	"fmt"
	"os"

	"github.com/pkg/errors"
)

// ProtocolVersion is the SFTP version implemented by this library. See the
// [spec](http://tools.ietf.org/html/draft-ietf-secsh-filexfer-02) and the
// [OpenSSH extensions](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL#L344)
// for reference.
const ProtocolVersion = 3

const (
	fxpInit          = 1
	fxpVersion       = 2
	fxpOpen          = 3
	fxpClose         = 4
	fxpRead          = 5
	fxpWrite         = 6
	fxpLstat         = 7
	fxpFstat         = 8
	fxpSetstat       = 9
	fxpFsetstat      = 10
	fxpOpendir       = 11
	fxpReaddir       = 12
	fxpRemove        = 13
	fxpMkdir         = 14
	fxpRmdir         = 15
	fxpRealpath      = 16
	fxpStat          = 17
	fxpRename        = 18
	fxpReadlink      = 19
	fxpSymlink       = 20
	fxpStatus        = 101
	fxpHandle        = 102
	fxpData          = 103
	fxpName          = 104
	fxpAttrs         = 105
	fxpExtended      = 200
	fxpExtendedReply = 201
)

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

	// see draft-ietf-secsh-filexfer-13
	// https://tools.ietf.org/html/draft-ietf-secsh-filexfer-13#section-9.1
	// ssh_FX_INVALID_HANDLE              = 9
	// ssh_FX_NO_SUCH_PATH                = 10
	// ssh_FX_FILE_ALREADY_EXISTS         = 11
	// ssh_FX_WRITE_PROTECT               = 12
	// ssh_FX_NO_MEDIA                    = 13
	// ssh_FX_NO_SPACE_ON_FILESYSTEM      = 14
	// ssh_FX_QUOTA_EXCEEDED              = 15
	// ssh_FX_UNKNOWN_PRINCIPAL           = 16
	// ssh_FX_LOCK_CONFLICT               = 17
	// ssh_FX_DIR_NOT_EMPTY               = 18
	// ssh_FX_NOT_A_DIRECTORY             = 19
	// ssh_FX_INVALID_FILENAME            = 20
	// ssh_FX_LINK_LOOP                   = 21
	// ssh_FX_CANNOT_DELETE               = 22
	// ssh_FX_INVALID_PARAMETER           = 23
	// ssh_FX_FILE_IS_A_DIRECTORY         = 24
	// ssh_FX_BYTE_RANGE_LOCK_CONFLICT    = 25
	// ssh_FX_BYTE_RANGE_LOCK_REFUSED     = 26
	// ssh_FX_DELETE_PENDING              = 27
	// ssh_FX_FILE_CORRUPT                = 28
	// ssh_FX_OWNER_INVALID               = 29
	// ssh_FX_GROUP_INVALID               = 30
	// ssh_FX_NO_MATCHING_BYTE_RANGE_LOCK = 31
)

// Bit flags for opening files (SSH_FXP_OPEN).
// https://tools.ietf.org/html/draft-ietf-secsh-filexfer-02#section-6.3
type pflag uint32

const (
	// PFlagRead means open the file for reading. This may be
	// used in combination with PFlagWrite.
	PFlagRead = pflag(1 << iota)
	// PFlagWrite means open the file for writing. This may be
	// used in combination with PFlagRead.
	PFlagWrite
	// PFlagAppend forces all writes to append data to the end of
	// any existing file (overrides PFlagTruncate).
	PFlagAppend
	// PFlagCreate means the file should be created if it does not
	// already exist.
	PFlagCreate
	// PFlagTruncate means an existing file must be truncated, i.e.
	// begin writing at index 0 and overwrite existing data. If this
	// flag is present, PFlagCreate MUST also be specified.
	PFlagTruncate
	// PFlagExclusive means the request should fail if the file
	// already exists.
	PFlagExclusive
)

// os converts SFTP pflags to file open flags recognized by the os package.
func (pf pflag) os() (f int) {
	if pf&PFlagRead != 0 {
		if pf&PFlagWrite != 0 {
			f |= os.O_RDWR
		} else {
			f |= os.O_RDONLY
		}
	} else if pf&PFlagWrite != 0 {
		f |= os.O_WRONLY
	}
	if pf&PFlagAppend != 0 {
		f |= os.O_APPEND
	}
	if pf&PFlagCreate != 0 {
		f |= os.O_CREATE
	}
	if pf&PFlagTruncate != 0 {
		f |= os.O_TRUNC
	}
	if pf&PFlagExclusive != 0 {
		f |= os.O_EXCL
	}
	return
}

type fxp uint8

func (f fxp) String() string {
	switch f {
	case fxpInit:
		return "SSH_FXP_INIT"
	case fxpVersion:
		return "SSH_FXP_VERSION"
	case fxpOpen:
		return "SSH_FXP_OPEN"
	case fxpClose:
		return "SSH_FXP_CLOSE"
	case fxpRead:
		return "SSH_FXP_READ"
	case fxpWrite:
		return "SSH_FXP_WRITE"
	case fxpLstat:
		return "SSH_FXP_LSTAT"
	case fxpFstat:
		return "SSH_FXP_FSTAT"
	case fxpSetstat:
		return "SSH_FXP_SETSTAT"
	case fxpFsetstat:
		return "SSH_FXP_FSETSTAT"
	case fxpOpendir:
		return "SSH_FXP_OPENDIR"
	case fxpReaddir:
		return "SSH_FXP_READDIR"
	case fxpRemove:
		return "SSH_FXP_REMOVE"
	case fxpMkdir:
		return "SSH_FXP_MKDIR"
	case fxpRmdir:
		return "SSH_FXP_RMDIR"
	case fxpRealpath:
		return "SSH_FXP_REALPATH"
	case fxpStat:
		return "SSH_FXP_STAT"
	case fxpRename:
		return "SSH_FXP_RENAME"
	case fxpReadlink:
		return "SSH_FXP_READLINK"
	case fxpSymlink:
		return "SSH_FXP_SYMLINK"
	case fxpStatus:
		return "SSH_FXP_STATUS"
	case fxpHandle:
		return "SSH_FXP_HANDLE"
	case fxpData:
		return "SSH_FXP_DATA"
	case fxpName:
		return "SSH_FXP_NAME"
	case fxpAttrs:
		return "SSH_FXP_ATTRS"
	case fxpExtended:
		return "SSH_FXP_EXTENDED"
	case fxpExtendedReply:
		return "SSH_FXP_EXTENDED_REPLY"
	default:
		return "unknown"
	}
}

type fx uint8

func (f fx) String() string {
	switch f {
	case fxOK:
		return "SSH_FX_OK"
	case fxEOF:
		return "SSH_FX_EOF"
	case fxNoSuchFile:
		return "SSH_FX_NO_SUCH_FILE"
	case fxPermissionDenied:
		return "SSH_FX_PERMISSION_DENIED"
	case fxFailure:
		return "SSH_FX_FAILURE"
	case fxBadMessage:
		return "SSH_FX_BAD_MESSAGE"
	case fxNoConnection:
		return "SSH_FX_NO_CONNECTION"
	case fxConnectionLost:
		return "SSH_FX_CONNECTION_LOST"
	case fxOpUnsupported:
		return "SSH_FX_OP_UNSUPPORTED"
	default:
		return "unknown"
	}
}

type unexpectedPacketErr struct {
	want, got uint8
}

func (u *unexpectedPacketErr) Error() string {
	return fmt.Sprintf("sftp: unexpected packet: want %v, got %v", fxp(u.want), fxp(u.got))
}

func unimplementedPacketErr(u uint8) error {
	return errors.Errorf("sftp: unimplemented packet type: got %v", fxp(u))
}

type unexpectedIDErr struct{ want, got uint32 }

func (u *unexpectedIDErr) Error() string {
	return fmt.Sprintf("sftp: unexpected id: want %v, got %v", u.want, u.got)
}

func unimplementedSeekWhence(whence int) error {
	return errors.Errorf("sftp: unimplemented seek whence %v", whence)
}

func unexpectedCount(want, got uint32) error {
	return errors.Errorf("sftp: unexpected count: want %v, got %v", want, got)
}

type unexpectedVersionErr struct{ want, got uint32 }

func (u *unexpectedVersionErr) Error() string {
	return fmt.Sprintf("sftp: unexpected server version: want %v, got %v", u.want, u.got)
}

// A StatusError is returned when an SFTP operation fails, and provides
// additional information about the failure.
type StatusError struct {
	Code      uint32
	msg, lang string
}

func (s *StatusError) Error() string { return fmt.Sprintf("sftp: %q (%v)", s.msg, fx(s.Code)) }
