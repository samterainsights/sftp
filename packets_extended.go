package sftp

import (
	"bytes"
	"encoding/binary"
)

// README
//
// This file contains (un)marshaling code for all supported extended packets, currently:
//
// 		- "posix-rename@openssh.com"
//		- "statvfs@openssh.com"
//
// Please add to this list if you implement another extended packet.

type fxpExtPosixRenamePkt struct {
	ID      uint32 // set externally from the SSH_FXP_EXTENDED wrapper
	OldPath string
	NewPath string
}

func (p *fxpExtPosixRenamePkt) id() uint32      { return p.ID }
func (p *fxpExtPosixRenamePkt) getPath() string { return p.Oldpath }
func (p *fxpExtPosixRenamePkt) notReadOnly()    {}

func (p *fxpExtPosixRenamePkt) MarshalBinary() ([]byte, error) {
	b := allocPkt(ssh_FXP_EXTENDED, 4+(4+len(p.OldPath))+(4+len(p.NewPath)))
	b = marshalUint32(b, p.ID)
	b = marshalString(b, "posix-rename@openssh.com")
	b = marshalString(b, p.Oldpath)
	return marshalString(b, p.Newpath), nil
}

func (p *fxpExtPosixRenamePkt) UnmarshalBinary(b []byte) (err error) {
	if p.OldPath, b, err = unmarshalStringSafe(b); err != nil {
		return
	}
	p.NewPath, _, err = unmarshalStringSafe(b)
	return
}

type fxpExtStatVFSPkt struct {
	ID   uint32
	Path string
}

func (p *fxpExtStatVFSPkt) id() uint32     { return p.ID }
func (p *fxpExtStatVFSPkt) readonly() bool { return true }

func (p *fxpExtStatVFSPkt) /*FIXME(samterainsights): encode length prefix*/ MarshalBinary() ([]byte, error) {
	l := 1 + 4 + // type(byte) + uint32
		len(p.Path) +
		len("statvfs@openssh.com")

	b := make([]byte, 0, l)
	b = append(b, ssh_FXP_EXTENDED)
	b = marshalUint32(b, p.ID)
	b = marshalString(b, "statvfs@openssh.com")
	b = marshalString(b, p.Path)
	return b, nil
}

// A StatVFS contains statistics about a filesystem.
type StatVFS struct {
	ID      uint32
	Bsize   uint64 /* file system block size */
	Frsize  uint64 /* fundamental fs block size */
	Blocks  uint64 /* number of blocks (unit f_frsize) */
	Bfree   uint64 /* free blocks in file system */
	Bavail  uint64 /* free blocks for non-root */
	Files   uint64 /* total file inodes */
	Ffree   uint64 /* free file inodes */
	Favail  uint64 /* free file inodes for to non-root */
	Fsid    uint64 /* file system id */
	Flag    uint64 /* bit mask of f_flag values */
	Namemax uint64 /* maximum filename length */
}

// TotalSpace calculates the amount of total space in a filesystem.
func (p *StatVFS) TotalSpace() uint64 {
	return p.Frsize * p.Blocks
}

// FreeSpace calculates the amount of free space in a filesystem.
func (p *StatVFS) FreeSpace() uint64 {
	return p.Frsize * p.Bfree
}

// MarshalBinary converts to ssh_FXP_EXTENDED_REPLY packet binary format
func (p *StatVFS) /*FIXME(samterainsights): encode length prefix*/ MarshalBinary() ([]byte, error) {
	var buf bytes.Buffer
	buf.Write([]byte{ssh_FXP_EXTENDED_REPLY})
	err := binary.Write(&buf, binary.BigEndian, p)
	return buf.Bytes(), err
}
