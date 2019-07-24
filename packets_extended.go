package sftp

// README
//
// This file contains (un)marshaling code for all supported extended packets, currently:
//
// 		- "posix-rename@openssh.com"
//		- "statvfs@openssh.com"
//		- TODO(samterainsights): "fstatvfs@openssh.com"
//		- TODO(samterainsights): "hardlink@openssh.com"
//		- TODO(samterainsights): "fsync@openssh.com"
//
// Please add to this list if you implement another extended packet.

// fxpExtPosixRenamePkt is an extended "posix-rename@openssh.com" request packet. It
// defers from SSH_FXP_RENAME in that POSIX renames are guaranteed to be atomic and
// thus cannot fail halfway through and leave multiple hard links to the same file,
// with the caveat that they are not supported on all OSs/filesystems.
type fxpExtPosixRenamePkt struct {
	ID      uint32 // set externally from the SSH_FXP_EXTENDED wrapper
	OldPath string
	NewPath string
}

func (p *fxpExtPosixRenamePkt) id() uint32 { return p.ID }

func (p *fxpExtPosixRenamePkt) MarshalBinary() ([]byte, error) {
	const ext = "posix-rename@openssh.com"
	b := allocPkt(ssh_FXP_EXTENDED, 4+(4+len(ext))+(4+len(p.OldPath))+(4+len(p.NewPath)))
	b = appendU32(b, p.ID)
	b = appendStr(b, ext)
	b = appendStr(b, p.OldPath)
	return appendStr(b, p.NewPath), nil
}

func (p *fxpExtPosixRenamePkt) UnmarshalBinary(b []byte) (err error) {
	if p.OldPath, b, err = takeStr(b); err != nil {
		return
	}
	p.NewPath, _, err = takeStr(b)
	return
}

// fxpExtStatvfsPkt is an extended "statvfs@openssh.com" request packet. It
// is used to obtain detailed information about an underlying virtual
// filesystem.
type fxpExtStatvfsPkt struct {
	ID   uint32 // set externally from the SSH_FXP_EXTENDED wrapper
	Path string
}

func (p *fxpExtStatvfsPkt) id() uint32 { return p.ID }

func (p *fxpExtStatvfsPkt) MarshalBinary() ([]byte, error) {
	const ext = "statvfs@openssh.com"
	b := allocPkt(ssh_FXP_EXTENDED, 4+(4+len(ext))+(4+len(p.Path)))
	b = appendU32(b, p.ID)
	b = appendStr(b, ext)
	return appendStr(b, p.Path), nil
}

func (p *fxpExtStatvfsPkt) UnmarshalBinary(b []byte) (err error) {
	p.Path, _, err = takeStr(b)
	return
}

// fxpExtVfsPkt is the success reply to an `statvfs@openssh.com` request.
type fxpExtVfsPkt struct {
	ID uint32
	StatVFS
}

func (p *fxpExtVfsPkt) id() uint32 { return p.ID }

func (p *fxpExtVfsPkt) MarshalBinary() ([]byte, error) {
	b := allocPkt(ssh_FXP_EXTENDED_REPLY, 4+(11*8)) // uint32 ID + 11 uint64s
	b = appendU32(b, p.ID)
	b = appendU64(b, p.BlockSize)
	b = appendU64(b, p.FBlockSize)
	b = appendU64(b, p.Blocks)
	b = appendU64(b, p.BlocksFree)
	b = appendU64(b, p.BlocksAvail)
	b = appendU64(b, p.Files)
	b = appendU64(b, p.FilesFree)
	b = appendU64(b, p.FilesAvail)
	b = appendU64(b, p.FSID)
	b = appendU64(b, p.Flag)
	return appendU64(b, p.MaxNameLen), nil
}

func (p *fxpExtVfsPkt) UnmarshalBinary(b []byte) (err error) {
	if p.ID, b, err = takeU32(b); err != nil {
		return
	}
	if p.BlockSize, b, err = takeU64(b); err != nil {
		return
	}
	if p.FBlockSize, b, err = takeU64(b); err != nil {
		return
	}
	if p.Blocks, b, err = takeU64(b); err != nil {
		return
	}
	if p.BlocksFree, b, err = takeU64(b); err != nil {
		return
	}
	if p.BlocksAvail, b, err = takeU64(b); err != nil {
		return
	}
	if p.Files, b, err = takeU64(b); err != nil {
		return
	}
	if p.FilesFree, b, err = takeU64(b); err != nil {
		return
	}
	if p.FilesAvail, b, err = takeU64(b); err != nil {
		return
	}
	if p.FSID, b, err = takeU64(b); err != nil {
		return
	}
	if p.Flag, b, err = takeU64(b); err != nil {
		return
	}
	p.MaxNameLen, _, err = takeU64(b)
	return
}

const (
	vfsFlagReadonly = 0x1
	vfsFlagNoSetUID = 0x2
)

// A StatVFS contains detailed information about a virtual filesystem.
type StatVFS struct {
	BlockSize   uint64
	FBlockSize  uint64 // fundamental block size
	Blocks      uint64 // number of fundamental blocks
	BlocksFree  uint64 // free blocks in file system
	BlocksAvail uint64 // free blocks for non-root
	Files       uint64 // total file inodes
	FilesFree   uint64 // free file inodes
	FilesAvail  uint64 // free file inodes for to non-root
	FSID        uint64 // file system id
	Flag        uint64 // bit mask of f_flag values
	MaxNameLen  uint64 // maximum filename length
}

// TotalSpace calculates the amount of total space in a filesystem.
func (fs *StatVFS) TotalSpace() uint64 {
	return fs.FBlockSize * fs.Blocks
}

// FreeSpace calculates the amount of free space in a filesystem.
func (fs *StatVFS) FreeSpace() uint64 {
	return fs.FBlockSize * fs.BlocksFree
}

// Readonly returns true if the filesystem is read-only.
func (fs *StatVFS) Readonly() bool {
	return fs.Flag&vfsFlagReadonly != 0
}

// SupportsSetUID returns true if the filesystem supports `setuid`.
func (fs *StatVFS) SupportsSetUID() bool {
	return fs.Flag&vfsFlagNoSetUID == 0
}
