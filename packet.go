package sftp

import (
	"bytes"
	"encoding"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"reflect"
	"time"

	"github.com/pkg/errors"
)

var (
	errShortPacket           = errors.New("packet too short")
	errUnknownExtendedPacket = errors.New("unknown extended packet")
)

func allocPkt(pktType byte, dataLen uint32) []byte {
	return append(marshalUint32(make([]byte, 0, 5+dataLen), dataLen+1), pktType)
}

func marshalUint32(b []byte, v uint32) []byte {
	return append(b, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

func marshalUint64(b []byte, v uint64) []byte {
	return marshalUint32(marshalUint32(b, uint32(v>>32)), uint32(v))
}

func marshalString(b []byte, v string) []byte {
	return append(marshalUint32(b, uint32(len(v))), v...)
}

func marshal(b []byte, v interface{}) []byte {
	if v == nil {
		return b
	}
	switch v := v.(type) {
	case uint8:
		return append(b, v)
	case uint32:
		return marshalUint32(b, v)
	case uint64:
		return marshalUint64(b, v)
	case string:
		return marshalString(b, v)
	case os.FileInfo:
		return marshalFileAttr(b, v)
	default:
		switch d := reflect.ValueOf(v); d.Kind() {
		case reflect.Struct:
			for i, n := 0, d.NumField(); i < n; i++ {
				b = append(marshal(b, d.Field(i).Interface()))
			}
			return b
		case reflect.Slice:
			for i, n := 0, d.Len(); i < n; i++ {
				b = append(marshal(b, d.Index(i).Interface()))
			}
			return b
		default:
			panic(fmt.Sprintf("marshal(%#v): cannot handle type %T", v, v))
		}
	}
}

func unmarshalUint32(b []byte) (uint32, []byte) {
	v := uint32(b[3]) | uint32(b[2])<<8 | uint32(b[1])<<16 | uint32(b[0])<<24
	return v, b[4:]
}

func unmarshalUint32Safe(b []byte) (uint32, []byte, error) {
	if len(b) >= 4 {
		// Inline binary.BigEndian.Uint32(b) in the hopes that the compiler is
		// smart enough to optimize out bounds checks since we checked above.
		v := uint32(b[3]) | uint32(b[2])<<8 | uint32(b[1])<<16 | uint32(b[0])<<24
		return v, b[4:], nil
	}
	return 0, nil, errShortPacket
}

func unmarshalUint64(b []byte) (uint64, []byte) {
	return binary.BigEndian.Uint64(b), b[8:]
}

func unmarshalUint64Safe(b []byte) (uint64, []byte, error) {
	if len(b) >= 8 {
		// Inline binary.BigEndian.Uint64(b) in the hopes that the compiler is
		// smart enough to optimize out bounds checks since we checked above.
		v := uint64(b[7]) | uint64(b[6])<<8 | uint64(b[5])<<16 | uint64(b[4])<<24 |
			uint64(b[3])<<32 | uint64(b[2])<<40 | uint64(b[1])<<48 | uint64(b[0])<<56
		return v, b[8:], nil
	}
	return 0, nil, errShortPacket
}

func unmarshalString(b []byte) (string, []byte) {
	n, b := unmarshalUint32(b)
	return string(b[:n]), b[n:]
}

func unmarshalStringSafe(b []byte) (string, []byte, error) {
	n, b, err := unmarshalUint32Safe(b)
	if err != nil {
		return "", nil, err
	}
	if int64(n) > int64(len(b)) {
		return "", nil, errShortPacket
	}
	return string(b[:n]), b[n:], nil
}

func marshalIDString(pktType byte, id uint32, str string) ([]byte, error) {
	// uint32 id + string something
	b := allocPkt(pktType, 4+(4+len(str)))
	b = marshalUint32(b, id)
	b = marshalString(b, str)
	return b, nil
}

func unmarshalIDString(b []byte, id *uint32, str *string) (err error) {
	if *id, b, err = unmarshalUint32Safe(b); err != nil {
		return
	}
	*str, _, err = unmarshalStringSafe(b)
	return
}

func unmarshalFileAttrSafe(b []byte) (_ *FileAttr, _ []byte, err error) {
	var attr FileAttr
	if attr.Flags, b, err = unmarshalUint32Safe(b); err != nil {
		return
	}
	if attr.Flags&attrFlagSize != 0 {
		if attr.Size, b, err = unmarshalUint64Safe(b); err != nil {
			return
		}
	}
	if attr.Flags&attrFlagUIDGID != 0 {
		if attr.UID, b, err = unmarshalUint32Safe(b); err != nil {
			return
		}
		if attr.GID, b, err = unmarshalUint32Safe(b); err != nil {
			return
		}
	}
	if attr.Flags&attrFlagPermissions != 0 {
		var perms uint32
		if perms, b, err = unmarshalUint32Safe(b); err != nil {
			return
		}
		attr.Perms = toFileMode(perms)
	}
	if attr.Flags&attrFlagAcModTime != 0 {
		var atime, mtime uint32
		if atime, b, err = unmarshalUint32Safe(b); err != nil {
			return
		}
		if mtime, b, err = unmarshalUint32Safe(b); err != nil {
			return
		}
		attr.AcTime = time.Unix(int64(atime), 0)
		attr.ModTime = time.Unix(int64(mtime), 0)
	}
	if attr.Flags&attrFlagExtended != 0 {
		var count uint32
		if count, b, err = unmarshalUint32Safe(b); err != nil {
			return
		}

		attr.Extensions = make([]StatExtended, count)
		for i := uint32(0); i < count; i++ {
			if attr.Extensions[i].ExtType, b, err = unmarshalStringSafe(b); err != nil {
				return
			}
			if attr.Extensions[i].ExtData, b, err = unmarshalStringSafe(b); err != nil {
				return
			}
		}
	}
	return &attr, b, nil
}

// writePacket marshals and writes a packet.
func writePacket(w io.Writer, pkt encoding.BinaryMarshaler) error {
	b, err := pkt.MarshalBinary()
	if err != nil {
		return errors.Wrap(err, "error marshaling packet")
	}
	debug("writePacket [type=%s]: %x", fxp(b[4]), b[5:])
	if _, err = w.Write(b); err != nil {
		return errors.Wrap(err, "error writing packet")
	}
	return nil
}

// readPacket reads a single SFTP packet and returns the raw type and
// data. The data will need to be interpreted depending on the type.
func readPacket(r io.Reader) (uint8, []byte, error) {
	b := make([]byte, 4)
	if _, err := io.ReadFull(r, b); err != nil {
		return 0, nil, err
	}
	pktLen := binary.BigEndian.Uint32(b)
	b = make([]byte, pktLen)
	if _, err := io.ReadFull(r, b); err != nil {
		debug("readPacket [length=%d]: error: %v", pktLen, err)
		return 0, nil, err
	}
	debug("readPacket [type=%s]: %x", fxp(b[0]), b[1:])
	return b[0], b[1:], nil
}

type extensionPair struct {
	Name string
	Data string
}

// README!
// Here begins the definition of packets along with their encoding.BinaryMarshaler/Unmarshaler implementations.
// Manually writing the marshalling logic is tedious but MUCH more efficient than using reflection.
// All packets encode their own uint32 length prefix (https://tools.ietf.org/html/draft-ietf-secsh-filexfer-02#section-3);
// this is also tedious but it is another big optimization which saves us a lot of copying when sending packets.

type fxpInitPkt struct {
	Version    uint32
	Extensions []extensionPair
}

func (p *fxpInitPkt) MarshalBinary() ([]byte, error) {
	dataLen := 4 // uint32 version
	for _, ext := range p.Extensions {
		l += (4 + len(ext.Name)) + (4 + len(ext.Data)) // string + string
	}
	b := allocPkt(ssh_FXP_INIT, dataLen)
	b = marshalUint32(b, p.Version)
	for _, ext := range p.Extensions {
		b = marshalString(b, ext.Name)
		b = marshalString(b, ext.Data)
	}
	return b, nil
}

func (p *fxpInitPkt) UnmarshalBinary(b []byte) (err error) {
	if p.Version, b, err = unmarshalUint32Safe(b); err != nil {
		return
	}
	for len(b) > 0 {
		var ext extensionPair
		if ext.Name, b, err = unmarshalStringSafe(b); err != nil {
			return
		}
		if ext.Data, b, err = unmarshalStringSafe(b); err != nil {
			return
		}
		p.Extensions = append(p.Extensions, ext)
	}
	return
}

// fxpVersionPkt is ALMOST identical to fxpInitPkt--type byte is different!
type fxpVersionPkt struct {
	Version    uint32
	Extensions []extensionPair
}

func (p *fxpVersionPkt) MarshalBinary() ([]byte, error) {
	dataLen := 4 // uint32 version
	for _, ext := range p.Extensions {
		l += (4 + len(ext.Name)) + (4 + len(ext.Data)) // string + string
	}
	b := allocPkt(ssh_FXP_VERSION, dataLen)
	b = marshalUint32(b, p.Version)
	for _, ext := range p.Extensions {
		b = marshalString(b, ext.Name)
		b = marshalString(b, ext.Data)
	}
	return b, nil
}

func (p *fxpVersionPkt) UnmarshalBinary(b []byte) (err error) {
	if p.Version, b, err = unmarshalUint32Safe(b); err != nil {
		return
	}
	for len(b) > 0 {
		var ext extensionPair
		if ext.Name, b, err = unmarshalStringSafe(b); err != nil {
			return
		}
		if ext.Data, b, err = unmarshalStringSafe(b); err != nil {
			return
		}
		p.Extensions = append(p.Extensions, ext)
	}
	return
}

type fxpOpenPkt struct {
	ID     uint32
	Path   string
	PFlags pflag
	Attr   *FileAttr
}

func (p *fxpOpenPkt) id() uint32 { return p.ID }

func (p *fxpOpenPkt) MarshalBinary() ([]byte, error) {
	// uint32 id + string filename + uint32 pflags + [file attributes]
	b := allocPkt(ssh_FXP_OPEN, 4+(4+len(p.Path))+4+p.Attr.encodedSize())
	b = marshalUint32(b, p.ID)
	b = marshalString(b, p.Path)
	b = marshalUint32(b, uint32(p.Pflags))
	// FIXME(samterainsights): actually marshal the file attributes,
	// but right now I'm pressed for server functionality.
	b = marshalUint32(b, 0) // empty flags = attributes never passed from client
	return b, nil
}

func (p *fxpOpenPkt) UnmarshalBinary(b []byte) (err error) {
	if p.ID, b, err = unmarshalUint32Safe(b); err != nil {
		return
	}
	if p.Path, b, err = unmarshalStringSafe(b); err != nil {
		return
	}
	if p.Pflags, b, err = unmarshalUint32Safe(b); err != nil {
		return
	}
	if p.Attr, b, err = unmarshalFileAttrSafe(b); err != nil {
		return
	}
	return
}

type fxpClosePkt struct {
	ID     uint32
	Handle string
}

func (p *fxpClosePkt) id() uint32 { return p.ID }

func (p *fxpClosePkt) MarshalBinary() ([]byte, error) {
	return marshalIDString(ssh_FXP_CLOSE, p.ID, p.Handle)
}

func (p *fxpClosePkt) UnmarshalBinary(b []byte) error {
	return unmarshalIDString(b, &p.ID, &p.Handle)
}

type fxpReadPkt struct {
	ID     uint32
	Handle string
	Offset uint64
	Len    uint32
}

func (p *fxpReadPkt) id() uint32 { return p.ID }

func (p *fxpReadPkt) MarshalBinary() ([]byte, error) {
	b := allocPkt(ssh_FXP_READ, 4+(4+len(p.Handle))+8+4)
	b = marshalUint32(b, p.ID)
	b = marshalString(b, p.Handle)
	b = marshalUint64(b, p.Offset)
	b = marshalUint32(b, p.Len)
	return b, nil
}

func (p *fxpReadPkt) UnmarshalBinary(b []byte) (err error) {
	if p.ID, b, err = unmarshalUint32Safe(b); err != nil {
		return
	}
	if p.Handle, b, err = unmarshalStringSafe(b); err != nil {
		return
	}
	if p.Offset, b, err = unmarshalUint64Safe(b); err != nil {
		return
	}
	if p.Len, _, err = unmarshalUint32Safe(b); err != nil {
		return
	}
	return
}

type fxpWritePkt struct {
	ID     uint32
	Handle string
	Offset uint64
	Length uint32
	Data   []byte
}

func (p fxpWritePkt) id() uint32 { return p.ID }

func (p fxpWritePkt) /*FIXME(samterainsights): encode length prefix*/ MarshalBinary() ([]byte, error) {
	l := 1 + 4 + // type(byte) + uint32
		4 + len(p.Handle) +
		8 + 4 + // uint64 + uint32
		len(p.Data)

	b := make([]byte, 0, l)
	b = append(b, ssh_FXP_WRITE)
	b = marshalUint32(b, p.ID)
	b = marshalString(b, p.Handle)
	b = marshalUint64(b, p.Offset)
	b = marshalUint32(b, p.Length)
	b = append(b, p.Data...)
	return b, nil
}

func (p *fxpWritePkt) UnmarshalBinary(b []byte) error {
	var err error
	if p.ID, b, err = unmarshalUint32Safe(b); err != nil {
		return err
	} else if p.Handle, b, err = unmarshalStringSafe(b); err != nil {
		return err
	} else if p.Offset, b, err = unmarshalUint64Safe(b); err != nil {
		return err
	} else if p.Length, b, err = unmarshalUint32Safe(b); err != nil {
		return err
	} else if uint32(len(b)) < p.Length {
		return errShortPacket
	}

	p.Data = append([]byte{}, b[:p.Length]...)
	return nil
}

type sshFxpRemovePacket struct {
	ID       uint32
	Filename string
}

type sshFxpReaddirPacket struct {
	ID     uint32
	Handle string
}

func (p sshFxpReaddirPacket) id() uint32 { return p.ID }

func (p sshFxpReaddirPacket) /*FIXME(samterainsights): encode length prefix*/ MarshalBinary() ([]byte, error) {
	return marshalIDString(ssh_FXP_READDIR, p.ID, p.Handle)
}

func (p *sshFxpReaddirPacket) UnmarshalBinary(b []byte) error {
	return unmarshalIDString(b, &p.ID, &p.Handle)
}

type sshFxpOpendirPacket struct {
	ID   uint32
	Path string
}

func (p sshFxpOpendirPacket) id() uint32 { return p.ID }

func (p sshFxpOpendirPacket) /*FIXME(samterainsights): encode length prefix*/ MarshalBinary() ([]byte, error) {
	return marshalIDString(ssh_FXP_OPENDIR, p.ID, p.Path)
}

func (p *sshFxpOpendirPacket) UnmarshalBinary(b []byte) error {
	return unmarshalIDString(b, &p.ID, &p.Path)
}

type sshFxpLstatPacket struct {
	ID   uint32
	Path string
}

func (p sshFxpLstatPacket) id() uint32 { return p.ID }

func (p sshFxpLstatPacket) /*FIXME(samterainsights): encode length prefix*/ MarshalBinary() ([]byte, error) {
	return marshalIDString(ssh_FXP_LSTAT, p.ID, p.Path)
}

func (p *sshFxpLstatPacket) UnmarshalBinary(b []byte) error {
	return unmarshalIDString(b, &p.ID, &p.Path)
}

type sshFxpStatPacket struct {
	ID   uint32
	Path string
}

func (p sshFxpStatPacket) id() uint32 { return p.ID }

func (p sshFxpStatPacket) /*FIXME(samterainsights): encode length prefix*/ MarshalBinary() ([]byte, error) {
	return marshalIDString(ssh_FXP_STAT, p.ID, p.Path)
}

func (p *sshFxpStatPacket) UnmarshalBinary(b []byte) error {
	return unmarshalIDString(b, &p.ID, &p.Path)
}

type sshFxpFstatPacket struct {
	ID     uint32
	Handle string
}

func (p sshFxpFstatPacket) id() uint32 { return p.ID }

func (p sshFxpFstatPacket) /*FIXME(samterainsights): encode length prefix*/ MarshalBinary() ([]byte, error) {
	return marshalIDString(ssh_FXP_FSTAT, p.ID, p.Handle)
}

func (p *sshFxpFstatPacket) UnmarshalBinary(b []byte) error {
	return unmarshalIDString(b, &p.ID, &p.Handle)
}

func (p sshFxpRemovePacket) id() uint32 { return p.ID }

func (p sshFxpRemovePacket) /*FIXME(samterainsights): encode length prefix*/ MarshalBinary() ([]byte, error) {
	return marshalIDString(ssh_FXP_REMOVE, p.ID, p.Filename)
}

func (p *sshFxpRemovePacket) UnmarshalBinary(b []byte) error {
	return unmarshalIDString(b, &p.ID, &p.Filename)
}

type sshFxpRmdirPacket struct {
	ID   uint32
	Path string
}

func (p sshFxpRmdirPacket) id() uint32 { return p.ID }

func (p sshFxpRmdirPacket) /*FIXME(samterainsights): encode length prefix*/ MarshalBinary() ([]byte, error) {
	return marshalIDString(ssh_FXP_RMDIR, p.ID, p.Path)
}

func (p *sshFxpRmdirPacket) UnmarshalBinary(b []byte) error {
	return unmarshalIDString(b, &p.ID, &p.Path)
}

type sshFxpSymlinkPacket struct {
	ID         uint32
	Targetpath string
	Linkpath   string
}

func (p sshFxpSymlinkPacket) id() uint32 { return p.ID }

func (p sshFxpSymlinkPacket) /*FIXME(samterainsights): encode length prefix*/ MarshalBinary() ([]byte, error) {
	l := 1 + 4 + // type(byte) + uint32
		4 + len(p.Targetpath) +
		4 + len(p.Linkpath)

	b := make([]byte, 0, l)
	b = append(b, ssh_FXP_SYMLINK)
	b = marshalUint32(b, p.ID)
	b = marshalString(b, p.Targetpath)
	b = marshalString(b, p.Linkpath)
	return b, nil
}

func (p *sshFxpSymlinkPacket) UnmarshalBinary(b []byte) error {
	var err error
	if p.ID, b, err = unmarshalUint32Safe(b); err != nil {
		return err
	} else if p.Targetpath, b, err = unmarshalStringSafe(b); err != nil {
		return err
	} else if p.Linkpath, _, err = unmarshalStringSafe(b); err != nil {
		return err
	}
	return nil
}

type sshFxpReadlinkPacket struct {
	ID   uint32
	Path string
}

func (p sshFxpReadlinkPacket) id() uint32 { return p.ID }

func (p sshFxpReadlinkPacket) /*FIXME(samterainsights): encode length prefix*/ MarshalBinary() ([]byte, error) {
	return marshalIDString(ssh_FXP_READLINK, p.ID, p.Path)
}

func (p *sshFxpReadlinkPacket) UnmarshalBinary(b []byte) error {
	return unmarshalIDString(b, &p.ID, &p.Path)
}

type sshFxpRealpathPacket struct {
	ID   uint32
	Path string
}

func (p sshFxpRealpathPacket) id() uint32 { return p.ID }

func (p sshFxpRealpathPacket) /*FIXME(samterainsights): encode length prefix*/ MarshalBinary() ([]byte, error) {
	return marshalIDString(ssh_FXP_REALPATH, p.ID, p.Path)
}

func (p *sshFxpRealpathPacket) UnmarshalBinary(b []byte) error {
	return unmarshalIDString(b, &p.ID, &p.Path)
}

type sshFxpNameAttr struct {
	Name     string
	LongName string
	Attrs    []interface{}
}

func (p sshFxpNameAttr) /*FIXME(samterainsights): encode length prefix*/ MarshalBinary() ([]byte, error) {
	b := []byte{}
	b = marshalString(b, p.Name)
	b = marshalString(b, p.LongName)
	for _, attr := range p.Attrs {
		b = marshal(b, attr)
	}
	return b, nil
}

type sshFxpNamePacket struct {
	ID        uint32
	NameAttrs []sshFxpNameAttr
}

func (p sshFxpNamePacket) /*FIXME(samterainsights): encode length prefix*/ MarshalBinary() ([]byte, error) {
	b := []byte{}
	b = append(b, ssh_FXP_NAME)
	b = marshalUint32(b, p.ID)
	b = marshalUint32(b, uint32(len(p.NameAttrs)))
	for _, na := range p.NameAttrs {
		ab, err := na.MarshalBinary()
		if err != nil {
			return nil, err
		}

		b = append(b, ab...)
	}
	return b, nil
}

type sshFxpRenamePacket struct {
	ID      uint32
	Oldpath string
	Newpath string
}

func (p sshFxpRenamePacket) id() uint32 { return p.ID }

func (p sshFxpRenamePacket) /*FIXME(samterainsights): encode length prefix*/ MarshalBinary() ([]byte, error) {
	l := 1 + 4 + // type(byte) + uint32
		4 + len(p.Oldpath) +
		4 + len(p.Newpath)

	b := make([]byte, 0, l)
	b = append(b, ssh_FXP_RENAME)
	b = marshalUint32(b, p.ID)
	b = marshalString(b, p.Oldpath)
	b = marshalString(b, p.Newpath)
	return b, nil
}

func (p *sshFxpRenamePacket) UnmarshalBinary(b []byte) error {
	var err error
	if p.ID, b, err = unmarshalUint32Safe(b); err != nil {
		return err
	} else if p.Oldpath, b, err = unmarshalStringSafe(b); err != nil {
		return err
	} else if p.Newpath, _, err = unmarshalStringSafe(b); err != nil {
		return err
	}
	return nil
}

type sshFxpPosixRenamePacket struct {
	ID      uint32
	Oldpath string
	Newpath string
}

func (p sshFxpPosixRenamePacket) id() uint32 { return p.ID }

func (p sshFxpPosixRenamePacket) /*FIXME(samterainsights): encode length prefix*/ MarshalBinary() ([]byte, error) {
	const ext = "posix-rename@openssh.com"
	l := 1 + 4 + // type(byte) + uint32
		4 + len(ext) +
		4 + len(p.Oldpath) +
		4 + len(p.Newpath)

	b := make([]byte, 0, l)
	b = append(b, ssh_FXP_EXTENDED)
	b = marshalUint32(b, p.ID)
	b = marshalString(b, ext)
	b = marshalString(b, p.Oldpath)
	b = marshalString(b, p.Newpath)
	return b, nil
}

type sshFxpMkdirPacket struct {
	ID    uint32
	Path  string
	Flags uint32 // ignored
}

func (p sshFxpMkdirPacket) id() uint32 { return p.ID }

func (p sshFxpMkdirPacket) /*FIXME(samterainsights): encode length prefix*/ MarshalBinary() ([]byte, error) {
	l := 1 + 4 + // type(byte) + uint32
		4 + len(p.Path) +
		4 // uint32

	b := make([]byte, 0, l)
	b = append(b, ssh_FXP_MKDIR)
	b = marshalUint32(b, p.ID)
	b = marshalString(b, p.Path)
	b = marshalUint32(b, p.Flags)
	return b, nil
}

func (p *sshFxpMkdirPacket) UnmarshalBinary(b []byte) error {
	var err error
	if p.ID, b, err = unmarshalUint32Safe(b); err != nil {
		return err
	} else if p.Path, b, err = unmarshalStringSafe(b); err != nil {
		return err
	} else if p.Flags, _, err = unmarshalUint32Safe(b); err != nil {
		return err
	}
	return nil
}

type sshFxpSetstatPacket struct {
	ID    uint32
	Path  string
	Flags uint32
	Attrs interface{}
}

type sshFxpFsetstatPacket struct {
	ID     uint32
	Handle string
	Flags  uint32
	Attrs  interface{}
}

func (p sshFxpSetstatPacket) id() uint32  { return p.ID }
func (p sshFxpFsetstatPacket) id() uint32 { return p.ID }

func (p sshFxpSetstatPacket) /*FIXME(samterainsights): encode length prefix*/ MarshalBinary() ([]byte, error) {
	l := 1 + 4 + // type(byte) + uint32
		4 + len(p.Path) +
		4 // uint32 + uint64

	b := make([]byte, 0, l)
	b = append(b, ssh_FXP_SETSTAT)
	b = marshalUint32(b, p.ID)
	b = marshalString(b, p.Path)
	b = marshalUint32(b, p.Flags)
	b = marshal(b, p.Attrs)
	return b, nil
}

func (p sshFxpFsetstatPacket) /*FIXME(samterainsights): encode length prefix*/ MarshalBinary() ([]byte, error) {
	l := 1 + 4 + // type(byte) + uint32
		4 + len(p.Handle) +
		4 // uint32 + uint64

	b := make([]byte, 0, l)
	b = append(b, ssh_FXP_FSETSTAT)
	b = marshalUint32(b, p.ID)
	b = marshalString(b, p.Handle)
	b = marshalUint32(b, p.Flags)
	b = marshal(b, p.Attrs)
	return b, nil
}

func (p *sshFxpSetstatPacket) UnmarshalBinary(b []byte) error {
	var err error
	if p.ID, b, err = unmarshalUint32Safe(b); err != nil {
		return err
	} else if p.Path, b, err = unmarshalStringSafe(b); err != nil {
		return err
	} else if p.Flags, b, err = unmarshalUint32Safe(b); err != nil {
		return err
	}
	p.Attrs = b
	return nil
}

func (p *sshFxpFsetstatPacket) UnmarshalBinary(b []byte) error {
	var err error
	if p.ID, b, err = unmarshalUint32Safe(b); err != nil {
		return err
	} else if p.Handle, b, err = unmarshalStringSafe(b); err != nil {
		return err
	} else if p.Flags, b, err = unmarshalUint32Safe(b); err != nil {
		return err
	}
	p.Attrs = b
	return nil
}

type sshFxpHandlePacket struct {
	ID     uint32
	Handle string
}

func (p sshFxpHandlePacket) /*FIXME(samterainsights): encode length prefix*/ MarshalBinary() ([]byte, error) {
	b := []byte{ssh_FXP_HANDLE}
	b = marshalUint32(b, p.ID)
	b = marshalString(b, p.Handle)
	return b, nil
}

type sshFxpStatusPacket struct {
	ID uint32
	StatusError
}

func (p sshFxpStatusPacket) /*FIXME(samterainsights): encode length prefix*/ MarshalBinary() ([]byte, error) {
	b := []byte{ssh_FXP_STATUS}
	b = marshalUint32(b, p.ID)
	b = marshalStatus(b, p.StatusError)
	return b, nil
}

type sshFxpDataPacket struct {
	ID     uint32
	Length uint32
	Data   []byte
}

func (p sshFxpDataPacket) /*FIXME(samterainsights): encode length prefix*/ MarshalBinary() ([]byte, error) {
	b := []byte{ssh_FXP_DATA}
	b = marshalUint32(b, p.ID)
	b = marshalUint32(b, p.Length)
	b = append(b, p.Data[:p.Length]...)
	return b, nil
}

func (p *sshFxpDataPacket) UnmarshalBinary(b []byte) error {
	var err error
	if p.ID, b, err = unmarshalUint32Safe(b); err != nil {
		return err
	} else if p.Length, b, err = unmarshalUint32Safe(b); err != nil {
		return err
	} else if uint32(len(b)) < p.Length {
		return errors.New("truncated packet")
	}

	p.Data = make([]byte, p.Length)
	copy(p.Data, b)
	return nil
}

type sshFxpStatvfsPacket struct {
	ID   uint32
	Path string
}

func (p sshFxpStatvfsPacket) id() uint32 { return p.ID }

func (p sshFxpStatvfsPacket) /*FIXME(samterainsights): encode length prefix*/ MarshalBinary() ([]byte, error) {
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

type sshFxpExtendedPacket struct {
	ID              uint32
	ExtendedRequest string
	SpecificPacket  interface {
		serverRespondablePacket
		readonly() bool
	}
}

func (p sshFxpExtendedPacket) id() uint32 { return p.ID }
func (p sshFxpExtendedPacket) readonly() bool {
	if p.SpecificPacket == nil {
		return true
	}
	return p.SpecificPacket.readonly()
}

func (p sshFxpExtendedPacket) respond(svr *Server) responsePacket {
	if p.SpecificPacket == nil {
		return statusFromError(p, nil)
	}
	return p.SpecificPacket.respond(svr)
}

func (p *sshFxpExtendedPacket) UnmarshalBinary(b []byte) error {
	var err error
	bOrig := b
	if p.ID, b, err = unmarshalUint32Safe(b); err != nil {
		return err
	} else if p.ExtendedRequest, _, err = unmarshalStringSafe(b); err != nil {
		return err
	}

	// specific unmarshalling
	switch p.ExtendedRequest {
	case "statvfs@openssh.com":
		p.SpecificPacket = &sshFxpExtendedPacketStatVFS{}
	case "posix-rename@openssh.com":
		p.SpecificPacket = &sshFxpExtendedPacketPosixRename{}
	default:
		return errors.Wrapf(errUnknownExtendedPacket, "packet type %v", p.SpecificPacket)
	}

	return p.SpecificPacket.UnmarshalBinary(bOrig)
}

type sshFxpExtendedPacketStatVFS struct {
	ID              uint32
	ExtendedRequest string
	Path            string
}

func (p sshFxpExtendedPacketStatVFS) id() uint32     { return p.ID }
func (p sshFxpExtendedPacketStatVFS) readonly() bool { return true }
func (p *sshFxpExtendedPacketStatVFS) UnmarshalBinary(b []byte) error {
	var err error
	if p.ID, b, err = unmarshalUint32Safe(b); err != nil {
		return err
	} else if p.ExtendedRequest, b, err = unmarshalStringSafe(b); err != nil {
		return err
	} else if p.Path, _, err = unmarshalStringSafe(b); err != nil {
		return err
	}
	return nil
}

type sshFxpExtendedPacketPosixRename struct {
	ID              uint32
	ExtendedRequest string
	Oldpath         string
	Newpath         string
}

func (p sshFxpExtendedPacketPosixRename) id() uint32     { return p.ID }
func (p sshFxpExtendedPacketPosixRename) readonly() bool { return false }
func (p *sshFxpExtendedPacketPosixRename) UnmarshalBinary(b []byte) error {
	var err error
	if p.ID, b, err = unmarshalUint32Safe(b); err != nil {
		return err
	} else if p.ExtendedRequest, b, err = unmarshalStringSafe(b); err != nil {
		return err
	} else if p.Oldpath, b, err = unmarshalStringSafe(b); err != nil {
		return err
	} else if p.Newpath, _, err = unmarshalStringSafe(b); err != nil {
		return err
	}
	return nil
}

func (p sshFxpExtendedPacketPosixRename) respond(s *Server) responsePacket {
	err := os.Rename(p.Oldpath, p.Newpath)
	return statusFromError(p, err)
}
