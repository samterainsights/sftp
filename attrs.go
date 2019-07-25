package sftp

// fxpAttrs support
// see http://tools.ietf.org/html/draft-ietf-secsh-filexfer-02#section-5

import (
	"os"
	"syscall"
	"time"
)

type attrFlag uint32

const (
	// AttrFlagSize indicates that the size field is present on a FileAttr.
	AttrFlagSize = attrFlag(1 << iota)

	// AttrFlagUIDGID indicates that the UID/GID fields are present on a
	// FileAttr.
	AttrFlagUIDGID

	// AttrFlagPermissions indicates that the permissions field is present
	// on a FileAttr.
	AttrFlagPermissions

	// AttrFlagAcModTime indicates the access time and modification time
	// fields are present on a FileAttr.
	AttrFlagAcModTime

	// -- room left in protocol for more flag bits --

	// AttrFlagExtended indicates that extensions are present on a FileAttr.
	AttrFlagExtended = attrFlag(1 << 31)
)

// fileInfo is an artificial type for wrapping a FileAttr with the os.FileInfo interface.
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

// FileAttr is a Golang idiomatic represention of the SFTP file attributes
// present on some requests, described here:
// https://tools.ietf.org/html/draft-ietf-secsh-filexfer-02#section-5
//
// TODO(samterainsights): validate flags on incoming packets and return a
// protocol error per the spec if unknown flags are set.
type FileAttr struct {
	Flags           attrFlag    // Indicates which fields were included on the packet
	Size            uint64      // Only valid if Flags&AttrFlagSize != 0
	UID, GID        uint32      // Only valid if Flags&AttrFlagUIDGID != 0
	Perms           os.FileMode // Only valid if Flags&AttrFlagPermissions != 0
	AcTime, ModTime time.Time   // Only valid if Flags&AttrFlagAcModTime != 0
	Extensions      []Extension // Only valid if Flags&AttrFlagExtended != 0
}

func (attr *FileAttr) encodedSize() int {
	size := 4 // uint32 flags
	if attr.Flags&AttrFlagSize != 0 {
		size += 8 // uint64 size
	}
	if attr.Flags&AttrFlagUIDGID != 0 {
		size += 8 // uint32 uid + uint32 gid
	}
	if attr.Flags&AttrFlagPermissions != 0 {
		size += 4 // uint32 permissions
	}
	if attr.Flags&AttrFlagAcModTime != 0 {
		size += 8 // uint32 atime + uint32 mtime
	}
	if attr.Flags&AttrFlagExtended != 0 {
		size += 4 // uint32 extended_count
		for _, ext := range attr.Extensions {
			// two strings, each: uint32 length + [data]
			size += 8 + len(ext.Name) + len(ext.Data)
		}
	}
	return size
}

func fileInfoFromStat(st *FileAttr, name string) os.FileInfo {
	fs := &fileInfo{
		name:  name,
		size:  int64(st.Size),
		mode:  st.Perms,
		mtime: st.ModTime,
		sys:   st,
	}
	return fs
}

func fileAttrFromInfo(fi os.FileInfo) *FileAttr {
	if attr, ok := fi.Sys().(*FileAttr); ok {
		return attr
	}

	mtime := fi.ModTime()
	attr := &FileAttr{
		Flags:   AttrFlagSize | AttrFlagPermissions | AttrFlagAcModTime,
		Size:    uint64(fi.Size()),
		Perms:   fi.Mode(),
		AcTime:  mtime,
		ModTime: mtime,
	}

	// OS-specific file stat decoding
	fileAttrFromInfoOS(fi, attr)

	return attr
}

func marshalFileInfo(b []byte, fi os.FileInfo) []byte {
	return appendAttr(b, fileAttrFromInfo(fi))
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

// fromFileMode converts from the os.FileMode specification to SFTP permission/mode bits
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
