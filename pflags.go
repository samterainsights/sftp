package sftp

import "os"

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
