package sftp

import (
	"encoding"
	"io"
	"sync"
)

// conn implements a bidirectional channel on which client and server
// connections are multiplexed.
type conn struct {
	io.Reader
	io.WriteCloser
	sync.Mutex // used to serialise writes to sendPacket
	// sendPacketTest is needed to replicate packet issues in testing
	sendPacketTest func(w io.Writer, m encoding.BinaryMarshaler) error
}

func (c *conn) sendPacket(m encoding.BinaryMarshaler) error {
	c.Lock()
	defer c.Unlock()
	if c.sendPacketTest != nil {
		return c.sendPacketTest(c, m)
	}
	return writePacket(c, m)
}

func (c *conn) sendError(p ider, err error) error {
	return c.sendPacket(statusFromError(p, err))
}
