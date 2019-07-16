package sftp

import "os"

// FileOpenFlags is the result of unpacking the `pflags` bitfield from an
// `SSH_FXP_OPEN` request. These flags correlate directly with the OS agnostic
// file open flags mentioned here: https://golang.org/pkg/os/#pkg-constants.
type FileOpenFlags struct {
	Read, Write, Append, Creat, Trunc, Excl bool
}

func newFileOpenFlags(flags uint32) FileOpenFlags {
	return FileOpenFlags{
		Read:   flags&ssh_FXF_READ != 0,
		Write:  flags&ssh_FXF_WRITE != 0,
		Append: flags&ssh_FXF_APPEND != 0,
		Creat:  flags&ssh_FXF_CREAT != 0,
		Trunc:  flags&ssh_FXF_TRUNC != 0,
		Excl:   flags&ssh_FXF_EXCL != 0,
	}
}

// Pflags converts the bitmap/uint32 from SFTP Open packet pflag values,
// into a FileOpenFlags struct with booleans set for flags set in bitmap.
func (r *Request) Pflags() FileOpenFlags {
	return newFileOpenFlags(r.Flags)
}

// FileAttrFlags is the result of unpacking the `flags` bitfield from the file
// attributes passed on some requests, e.g. `SSH_FXP_SETSTAT`. The flags
// determine which attributes are included: if the `SSH_FILEXFER_ATTR_SIZE` bit
// is set (`attr.Size == true`), then the provided attributes are expected to
// contain a `uint64` specifying the file size.
type FileAttrFlags struct {
	Size, UIDGID, Permissions, Acmodtime, Extended bool
}

func newFileAttrFlags(flags uint32) FileAttrFlags {
	return FileAttrFlags{
		Size:        flags&sftpAttrFlagSize != 0,
		UIDGID:      flags&sftpAttrFlagUIDGID != 0,
		Permissions: flags&sftpAttrFlagPermissions != 0,
		Acmodtime:   flags&sftpAttrFlagAcModTime != 0,
		Extended:    flags&sftpAttrFlagExtended != 0,
	}
}

// AttrFlags returns a FileAttrFlags boolean struct based on the bitmap/uint32 file
// attribute flags from the SFTP packaet.
func (r *Request) AttrFlags() FileAttrFlags {
	return newFileAttrFlags(r.Flags)
}

// FileMode returns the Mode SFTP file attributes wrapped as os.FileMode
func (a FileStat) FileMode() os.FileMode {
	return os.FileMode(a.Mode)
}

// Attributes parses file attributes byte blob and return them in a
// FileStat object.
func (r *Request) Attributes() *FileStat {
	stat, _ := getFileStat(r.Flags, r.Attrs)
	return stat
}
