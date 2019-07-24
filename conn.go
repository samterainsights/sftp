package sftp

import (
	"encoding"
	"io"
)

// conn implements packetSender on top of an io.ReadWriter and needs
// to be removed, just like packetSender.
type conn struct {
	io.ReadWriter
}

func (c *conn) sendPacket(pkt encoding.BinaryMarshaler) error {
	return writePacket(c, pkt)
}

func (c *conn) sendError(pkt ider, err error) error {
	return c.sendPacket(statusFromError(pkt, err))
}
