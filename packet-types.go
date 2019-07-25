// Package sftp implements the SSH File Transfer Protocol as described in
// https://tools.ietf.org/html/draft-ietf-secsh-filexfer-02
package sftp

import (
	"encoding"
	"fmt"

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

// fxp is a packet type.
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

type ider interface {
	id() uint32
}

// all incoming packets
type requestPacket interface {
	encoding.BinaryUnmarshaler
	ider
}

type responsePacket interface {
	encoding.BinaryMarshaler
	ider
}

// take raw incoming packet data and build packet objects
func makePacket(pktType fxp, pktData []byte) (requestPacket, error) {
	var pkt requestPacket

	switch pktType {
	case fxpInit:
		pkt = &fxpInitPkt{}
	case fxpLstat:
		pkt = &fxpLstatPkt{}
	case fxpOpen:
		pkt = &fxpOpenPkt{}
	case fxpClose:
		pkt = &fxpClosePkt{}
	case fxpRead:
		pkt = &fxpReadPkt{}
	case fxpWrite:
		pkt = &fxpWritePkt{}
	case fxpFstat:
		pkt = &fxpFstatPkt{}
	case fxpSetstat:
		pkt = &fxpSetstatPkt{}
	case fxpFsetstat:
		pkt = &fxpFsetstatPkt{}
	case fxpOpendir:
		pkt = &fxpOpendirPkt{}
	case fxpReaddir:
		pkt = &fxpReaddirPkt{}
	case fxpRemove:
		pkt = &fxpRemovePkt{}
	case fxpMkdir:
		pkt = &fxpMkdirPkt{}
	case fxpRmdir:
		pkt = &fxpRmdirPkt{}
	case fxpRealpath:
		pkt = &fxpRealpathPkt{}
	case fxpStat:
		pkt = &fxpStatPkt{}
	case fxpRename:
		pkt = &fxpRenamePkt{}
	case fxpReadlink:
		pkt = &fxpReadlinkPkt{}
	case fxpSymlink:
		pkt = &fxpSymlinkPkt{}
	case fxpExtended:
		pkt = &fxpExtendedPkt{}
	default:
		return nil, errors.Errorf("unknown packet type: %d", pktType)
	}

	// If an error occurs, still return the partially unpacked packet to allow callers
	// to return error messages appropriately with necessary id() method.
	return pkt, pkt.UnmarshalBinary(pktData)
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
