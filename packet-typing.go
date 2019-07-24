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
