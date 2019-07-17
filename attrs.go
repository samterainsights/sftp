package sftp

// ssh_FXP_ATTRS support
// see http://tools.ietf.org/html/draft-ietf-secsh-filexfer-02#section-5

import (
	"os"
	"syscall"
	"time"
)

const (
	sftpAttrFlagSize uint32 = 1 << iota
	sftpAttrFlagUIDGID
	sftpAttrFlagPermissions
	sftpAttrFlagAcModTime
	// -- room left in protocol for more flag bits --
	sftpAttrFlagExtended uint32 = 1 << 31
)

// fileInfo is an artificial type designed to satisfy os.FileInfo.
type fileInfo struct {
	name  string
	size  int64
	mode  os.FileMode
	mtime time.Time
	sys   interface{}
}

func (fi *fileInfo) Name() string       { return fi.name }
func (fi *fileInfo) Size() int64        { return fi.size }
func (fi *fileInfo) Mode() os.FileMode  { return fi.mode }
func (fi *fileInfo) ModTime() time.Time { return fi.mtime }
func (fi *fileInfo) IsDir() bool        { return fi.Mode().IsDir() }
func (fi *fileInfo) Sys() interface{}   { return fi.sys }

// FileStat holds the original unmarshalled values from a call to READDIR or
// *STAT. It is exported for the purposes of accessing the raw values via
// os.FileInfo.Sys(). It is also used server side to store the unmarshalled
// values for SetStat.
type FileStat struct {
	Size     uint64
	Mode     uint32
	Mtime    uint32
	Atime    uint32
	UID      uint32
	GID      uint32
	Extended []StatExtended
}

// StatExtended contains additional, extended information for a FileStat.
type StatExtended struct {
	ExtType string
	ExtData string
}

func fileInfoFromStat(st *FileStat, name string) os.FileInfo {
	fs := &fileInfo{
		name:  name,
		size:  int64(st.Size),
		mode:  toFileMode(st.Mode),
		mtime: time.Unix(int64(st.Mtime), 0),
		sys:   st,
	}
	return fs
}

func fileStatFromInfo(fi os.FileInfo) (uint32, FileStat) {
	mtime := fi.ModTime().Unix()
	flags := sftpAttrFlagSize | sftpAttrFlagPermissions | sftpAttrFlagAcModTime
	fileStat := FileStat{
		Size:  uint64(fi.Size()),
		Mode:  fromFileMode(fi.Mode()),
		Mtime: uint32(mtime),
		Atime: uint32(mtime),
	}

	// OS-specific file stat decoding
	fileStatFromInfoOs(fi, &flags, &fileStat)

	return flags, fileStat
}

func unmarshalAttrs(b []byte) (*FileStat, []byte) {
	flags, b := unmarshalUint32(b)
	return getFileStat(flags, b)
}

func marshalFileInfo(b []byte, fi os.FileInfo) []byte {
	// attributes variable struct, and also variable per protocol version
	// spec version 3 attributes:
	// uint32   flags
	// uint64   size           present only if flag SSH_FILEXFER_ATTR_SIZE
	// uint32   uid            present only if flag SSH_FILEXFER_ATTR_UIDGID
	// uint32   gid            present only if flag SSH_FILEXFER_ATTR_UIDGID
	// uint32   permissions    present only if flag SSH_FILEXFER_ATTR_PERMISSIONS
	// uint32   atime          present only if flag SSH_FILEXFER_ACMODTIME
	// uint32   mtime          present only if flag SSH_FILEXFER_ACMODTIME
	// uint32   extended_count present only if flag SSH_FILEXFER_ATTR_EXTENDED
	// string   extended_type
	// string   extended_data
	// ...      more extended data (extended_type - extended_data pairs),
	// 	   so that number of pairs equals extended_count

	flags, fileStat := fileStatFromInfo(fi)

	b = marshalUint32(b, flags)
	if flags&sftpAttrFlagSize != 0 {
		b = marshalUint64(b, fileStat.Size)
	}
	if flags&sftpAttrFlagUIDGID != 0 {
		b = marshalUint32(b, fileStat.UID)
		b = marshalUint32(b, fileStat.GID)
	}
	if flags&sftpAttrFlagPermissions != 0 {
		b = marshalUint32(b, fileStat.Mode)
	}
	if flags&sftpAttrFlagAcModTime != 0 {
		b = marshalUint32(b, fileStat.Atime)
		b = marshalUint32(b, fileStat.Mtime)
	}

	return b
}

// toFileMode converts sftp filemode bits to the os.FileMode specification
func toFileMode(mode uint32) os.FileMode {
	var fm = os.FileMode(mode & 0777)
	switch mode & syscall.S_IFMT {
	case syscall.S_IFBLK:
		fm |= os.ModeDevice
	case syscall.S_IFCHR:
		fm |= os.ModeDevice | os.ModeCharDevice
	case syscall.S_IFDIR:
		fm |= os.ModeDir
	case syscall.S_IFIFO:
		fm |= os.ModeNamedPipe
	case syscall.S_IFLNK:
		fm |= os.ModeSymlink
	case syscall.S_IFREG:
		// nothing to do
	case syscall.S_IFSOCK:
		fm |= os.ModeSocket
	}
	if mode&syscall.S_ISGID != 0 {
		fm |= os.ModeSetgid
	}
	if mode&syscall.S_ISUID != 0 {
		fm |= os.ModeSetuid
	}
	if mode&syscall.S_ISVTX != 0 {
		fm |= os.ModeSticky
	}
	return fm
}

// fromFileMode converts from the os.FileMode specification to sftp filemode bits
func fromFileMode(mode os.FileMode) uint32 {
	ret := uint32(0)

	if mode&os.ModeDevice != 0 {
		if mode&os.ModeCharDevice != 0 {
			ret |= syscall.S_IFCHR
		} else {
			ret |= syscall.S_IFBLK
		}
	}
	if mode&os.ModeDir != 0 {
		ret |= syscall.S_IFDIR
	}
	if mode&os.ModeSymlink != 0 {
		ret |= syscall.S_IFLNK
	}
	if mode&os.ModeNamedPipe != 0 {
		ret |= syscall.S_IFIFO
	}
	if mode&os.ModeSetgid != 0 {
		ret |= syscall.S_ISGID
	}
	if mode&os.ModeSetuid != 0 {
		ret |= syscall.S_ISUID
	}
	if mode&os.ModeSticky != 0 {
		ret |= syscall.S_ISVTX
	}
	if mode&os.ModeSocket != 0 {
		ret |= syscall.S_IFSOCK
	}

	if mode&os.ModeType == 0 {
		ret |= syscall.S_IFREG
	}
	ret |= uint32(mode & os.ModePerm)

	return ret
}
