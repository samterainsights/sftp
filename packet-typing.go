package sftp

import (
	"encoding"

	"github.com/pkg/errors"
)

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
	case ssh_FXP_LSTAT:
		pkt = &fxpLstatPkt{}
	case ssh_FXP_OPEN:
		pkt = &fxpOpenPkt{}
	case ssh_FXP_CLOSE:
		pkt = &fxpClosePkt{}
	case ssh_FXP_READ:
		pkt = &fxpReadPkt{}
	case ssh_FXP_WRITE:
		pkt = &fxpWritePkt{}
	case ssh_FXP_FSTAT:
		pkt = &fxpFstatPkt{}
	case ssh_FXP_SETSTAT:
		pkt = &fxpSetstatPkt{}
	case ssh_FXP_FSETSTAT:
		pkt = &fxpFsetstatPkt{}
	case ssh_FXP_OPENDIR:
		pkt = &fxpOpendirPkt{}
	case ssh_FXP_READDIR:
		pkt = &fxpReaddirPkt{}
	case ssh_FXP_REMOVE:
		pkt = &fxpRemovePkt{}
	case ssh_FXP_MKDIR:
		pkt = &fxpMkdirPkt{}
	case ssh_FXP_RMDIR:
		pkt = &fxpRmdirPkt{}
	case ssh_FXP_REALPATH:
		pkt = &fxpRealpathPkt{}
	case ssh_FXP_STAT:
		pkt = &fxpStatPkt{}
	case ssh_FXP_RENAME:
		pkt = &fxpRenamePkt{}
	case ssh_FXP_READLINK:
		pkt = &fxpReadlinkPkt{}
	case ssh_FXP_SYMLINK:
		pkt = &fxpSymlinkPkt{}
	case ssh_FXP_EXTENDED:
		pkt = &fxpExtendedPkt{}
	default:
		return nil, errors.Errorf("unknown packet type: %d", pktType)
	}

	// If an error occurs, still return the partially unpacked packet to allow callers
	// to return error messages appropriately with necessary id() method.
	return pkt, pkt.UnmarshalBinary(pktData)
}
