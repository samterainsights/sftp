package sftp

import (
	"encoding"

	"github.com/pkg/errors"
)

// all incoming packets
type requestPacket interface {
	encoding.BinaryUnmarshaler
	id() uint32
}

type responsePacket interface {
	encoding.BinaryMarshaler
	id() uint32
}

// interfaces to group types
type hasPath interface {
	requestPacket
	getPath() string
}

type hasHandle interface {
	requestPacket
	getHandle() string
}

type notReadOnly interface {
	notReadOnly()
}

//// define types by adding methods
// hasPath
func (p sshFxpLstatPacket) getPath() string    { return p.Path }
func (p sshFxpStatPacket) getPath() string     { return p.Path }
func (p sshFxpRmdirPacket) getPath() string    { return p.Path }
func (p sshFxpReadlinkPacket) getPath() string { return p.Path }
func (p sshFxpRealpathPacket) getPath() string { return p.Path }
func (p sshFxpMkdirPacket) getPath() string    { return p.Path }
func (p sshFxpSetstatPacket) getPath() string  { return p.Path }
func (p sshFxpStatvfsPacket) getPath() string  { return p.Path }
func (p sshFxpRemovePacket) getPath() string   { return p.Filename }
func (p sshFxpRenamePacket) getPath() string   { return p.Oldpath }
func (p sshFxpSymlinkPacket) getPath() string  { return p.Targetpath }
func (p sshFxpOpendirPacket) getPath() string  { return p.Path }
func (p fxpOpenPkt) getPath() string     { return p.Path }

func (p sshFxpExtendedPacketPosixRename) getPath() string { return p.Oldpath }

// hasHandle
func (p sshFxpFstatPacket) getHandle() string    { return p.Handle }
func (p sshFxpFsetstatPacket) getHandle() string { return p.Handle }
func (p fxpReadPkt) getHandle() string     { return p.Handle }
func (p fxpWritePkt) getHandle() string    { return p.Handle }
func (p sshFxpReaddirPacket) getHandle() string  { return p.Handle }
func (p fxpClosePkt) getHandle() string    { return p.Handle }

// notReadOnly
func (p fxpWritePkt) notReadOnly()               {}
func (p sshFxpSetstatPacket) notReadOnly()             {}
func (p sshFxpFsetstatPacket) notReadOnly()            {}
func (p sshFxpRemovePacket) notReadOnly()              {}
func (p sshFxpMkdirPacket) notReadOnly()               {}
func (p sshFxpRmdirPacket) notReadOnly()               {}
func (p sshFxpRenamePacket) notReadOnly()              {}
func (p sshFxpSymlinkPacket) notReadOnly()             {}
func (p sshFxpExtendedPacketPosixRename) notReadOnly() {}

// some packets with ID are missing id()
func (p sshFxpDataPacket) id() uint32   { return p.ID }
func (p sshFxpStatusPacket) id() uint32 { return p.ID }
func (p sshFxpStatResponse) id() uint32 { return p.ID }
func (p sshFxpNamePacket) id() uint32   { return p.ID }
func (p sshFxpHandlePacket) id() uint32 { return p.ID }
func (p StatVFS) id() uint32            { return p.ID }
func (p fxpVersionPkt) id() uint32 { return 0 }

// take raw incoming packet data and build packet objects
func makePacket(p rxPacket) (requestPacket, error) {
	var pkt requestPacket

	switch p.pktType {
	case ssh_FXP_INIT:
		pkt = &fxpInitPkt{}
	case ssh_FXP_LSTAT:
		pkt = &sshFxpLstatPacket{}
	case ssh_FXP_OPEN:
		pkt = &fxpOpenPkt{}
	case ssh_FXP_CLOSE:
		pkt = &fxpClosePkt{}
	case ssh_FXP_READ:
		pkt = &fxpReadPkt{}
	case ssh_FXP_WRITE:
		pkt = &fxpWritePkt{}
	case ssh_FXP_FSTAT:
		pkt = &sshFxpFstatPacket{}
	case ssh_FXP_SETSTAT:
		pkt = &sshFxpSetstatPacket{}
	case ssh_FXP_FSETSTAT:
		pkt = &sshFxpFsetstatPacket{}
	case ssh_FXP_OPENDIR:
		pkt = &sshFxpOpendirPacket{}
	case ssh_FXP_READDIR:
		pkt = &sshFxpReaddirPacket{}
	case ssh_FXP_REMOVE:
		pkt = &sshFxpRemovePacket{}
	case ssh_FXP_MKDIR:
		pkt = &sshFxpMkdirPacket{}
	case ssh_FXP_RMDIR:
		pkt = &sshFxpRmdirPacket{}
	case ssh_FXP_REALPATH:
		pkt = &sshFxpRealpathPacket{}
	case ssh_FXP_STAT:
		pkt = &sshFxpStatPacket{}
	case ssh_FXP_RENAME:
		pkt = &sshFxpRenamePacket{}
	case ssh_FXP_READLINK:
		pkt = &sshFxpReadlinkPacket{}
	case ssh_FXP_SYMLINK:
		pkt = &sshFxpSymlinkPacket{}
	case ssh_FXP_EXTENDED:
		pkt = &sshFxpExtendedPacket{}
	default:
		return nil, errors.Errorf("unknown packet type: %d", p.pktType)
	}

	// If an error occurs, still return the partially unpacked packet to allow callers
	// to return error messages appropriately with necessary id() method.
	return pkt, pkt.UnmarshalBinary(p.pktBytes)
}
