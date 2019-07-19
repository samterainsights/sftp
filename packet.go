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

// allocPkt allocates a buffer large enough to hold an overarching length prefix,
// packet type byte, and the given amount of data. Fills in the packet length and
// type. The goal is to allocate exactly once each time we marshal a packet.
// See https://tools.ietf.org/html/draft-ietf-secsh-filexfer-02#section-3.
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

func marshalFileAttr(b []byte, attr *FileAttr) []byte {
	flags := attr.Flags
	b = marshalUint32(b, uint32(flags))

	if flags&attrFlagSize != 0 {
		b = marshalUint64(b, attr.Size)
	}
	if flags&attrFlagUIDGID != 0 {
		b = marshalUint32(b, attr.UID)
		b = marshalUint32(b, attr.GID)
	}
	if flags&attrFlagPermissions != 0 {
		b = marshalUint32(b, fromFileMode(attr.Perms))
	}
	if flags&attrFlagAcModTime != 0 {
		b = marshalUint32(b, uint32(attr.AcTime.Unix()))
		b = marshalUint32(b, uint32(attr.ModTime.Unix()))
	}
	if flags&attrFlagExtended != 0 {
		b = marshalUint32(b, len(attr.Extensions))
		for _, ext := range attr.Extensions {
			b = marshalString(b, ext.ExtType)
			b = marshalString(b, ext.ExtData)
		}
	}

	return b
}

// marshalIDString is a convenience function to marshal a packet type, uint32 ID, and
// a string. Many packet types have this shape, hence this function's existence.
func marshalIDString(pktType byte, id uint32, str string) ([]byte, error) {
	b := allocPkt(pktType, 4+(4+len(str)))
	b = marshalUint32(b, id)
	return marshalString(b, str), nil
}

// marshalIDStringAttr is a convenience function identical to marshalIDString except it
// also includes file attributes.
func marshalIDStringAttr(pktType byte, id uint32, str string, attr *FileAttr) ([]byte, error) {
	b := allocPkt(pktType, 4+(4+len(str))+attr.encodedSize())
	b = marshalUint32(b, id)
	b = marshalString(b, str)
	return marshalFileAttr(b, attr), nil
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
		return marshalFileInfo(b, v)
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

// unmarshalIDString is a convenience function to unmarshal a packet which contains a uint32 ID and
// some string, in that order. Many packet types have this shape, hence this function's existence.
func unmarshalIDString(b []byte, id *uint32, str *string) (err error) {
	if *id, b, err = unmarshalUint32Safe(b); err != nil {
		return
	}
	*str, _, err = unmarshalStringSafe(b)
	return
}

// unmarshalIDStringAttr is a convenience function identical to unmarshalIDString except it also
// unmarshals file attributes.
func unmarshalIDStringAttr(b []byte, id *uint32, str *string, attr **FileAttr) (err error) {
	if *id, b, err = unmarshalUint32Safe(b); err != nil {
		return
	}
	if *str, b, err = unmarshalStringSafe(b); err != nil {
		return
	}
	*attr, _, err = unmarshalFileAttrSafe(b)
	return
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

// CLIENT -> SERVER PACKETS

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
	b = marshalFileAttr(b, p.Attr)
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
	Data   []byte
}

func (p *fxpWritePkt) id() uint32 { return p.ID }

func (p *fxpWritePkt) MarshalBinary() ([]byte, error) {
	b := allocPkt(ssh_FXP_WRITE, 4+(4+len(p.Handle))+8+(4+len(p.Data)))
	b = marshalUint32(b, p.ID)
	b = marshalString(b, p.Handle)
	b = marshalUint64(b, p.Offset)
	b = marshalUint32(b, len(p.Data))
	b = append(b, p.Data...)
	return b, nil
}

func (p *fxpWritePkt) UnmarshalBinary(b []byte) (err error) {
	if p.ID, b, err = unmarshalUint32Safe(b); err != nil {
		return
	}
	if p.Handle, b, err = unmarshalStringSafe(b); err != nil {
		return
	}
	if p.Offset, b, err = unmarshalUint64Safe(b); err != nil {
		return
	}

	var dataLen uint32
	if dataLen, b, err = unmarshalUint32Safe(b); err != nil {
		return
	}
	if len(b) < dataLen {
		return errShortPacket
	}
	p.Data = b[:dataLen]

	return nil
}

type fxpRemovePkt struct {
	ID   uint32
	Path string
}

func (p *fxpRemovePkt) id() uint32 { return p.ID }

func (p *fxpRemovePkt) MarshalBinary() ([]byte, error) {
	return marshalIDString(ssh_FXP_REMOVE, p.ID, p.Path)
}

func (p *fxpRemovePkt) UnmarshalBinary(b []byte) error {
	return unmarshalIDString(b, &p.ID, &p.Path)
}

type fxpRenamePkt struct {
	ID      uint32
	OldPath string
	NewPath string
}

func (p *fxpRenamePkt) id() uint32 { return p.ID }

func (p *fxpRenamePkt) MarshalBinary() ([]byte, error) {
	b := allocPkt(ssh_FXP_RENAME, 4+(4+len(p.OldPath))+(4+len(p.NewPath)))
	b = marshalUint32(b, p.ID)
	b = marshalString(b, p.Oldpath)
	b = marshalString(b, p.Newpath)
	return b, nil
}

func (p *fxpRenamePkt) UnmarshalBinary(b []byte) (err error) {
	if p.ID, b, err = unmarshalUint32Safe(b); err != nil {
		return
	}
	if p.OldPath, b, err = unmarshalStringSafe(b); err != nil {
		return
	}
	p.NewPath, _, err = unmarshalStringSafe(b)
	return
}

type fxpMkdirPkt struct {
	ID   uint32
	Path string
	Attr *FileAttr
}

func (p *fxpMkdirPkt) id() uint32 { return p.ID }

func (p *fxpMkdirPkt) MarshalBinary() ([]byte, error) {
	return marshalIDStringAttr(ssh_FXP_MKDIR, p.ID, p.Path, p.Attr)
}

func (p *fxpMkdirPkt) UnmarshalBinary(b []byte) error {
	return unmarshalIDStringAttr(b, &p.ID, &p.Path, &p.Attr)
}

type fxpRmdirPkt struct {
	ID   uint32
	Path string
}

func (p *fxpRmdirPkt) id() uint32 { return p.ID }

func (p *fxpRmdirPkt) MarshalBinary() ([]byte, error) {
	return marshalIDString(ssh_FXP_RMDIR, p.ID, p.Path)
}

func (p *fxpRmdirPkt) UnmarshalBinary(b []byte) error {
	return unmarshalIDString(b, &p.ID, &p.Path)
}

type fxpOpendirPkt struct {
	ID   uint32
	Path string
}

func (p *fxpOpendirPkt) id() uint32 { return p.ID }

func (p *fxpOpendirPkt) MarshalBinary() ([]byte, error) {
	return marshalIDString(ssh_FXP_OPENDIR, p.ID, p.Path)
}

func (p *fxpOpendirPkt) UnmarshalBinary(b []byte) error {
	return unmarshalIDString(b, &p.ID, &p.Path)
}

type fxpReaddirPkt struct {
	ID     uint32
	Handle string
}

func (p *fxpReaddirPkt) id() uint32 { return p.ID }

func (p *fxpReaddirPkt) MarshalBinary() ([]byte, error) {
	return marshalIDString(ssh_FXP_READDIR, p.ID, p.Handle)
}

func (p *fxpReaddirPkt) UnmarshalBinary(b []byte) error {
	return unmarshalIDString(b, &p.ID, &p.Handle)
}

// fxpStatPkt is used to request a file/directory's attributes.
// Symlinks are followed, i.e. statting a symlink returns info
// on the node it points to.
type fxpStatPkt struct {
	ID   uint32
	Path string
}

func (p *fxpStatPkt) id() uint32 { return p.ID }

func (p *fxpStatPkt) MarshalBinary() ([]byte, error) {
	return marshalIDString(ssh_FXP_STAT, p.ID, p.Path)
}

func (p *fxpStatPkt) UnmarshalBinary(b []byte) error {
	return unmarshalIDString(b, &p.ID, &p.Path)
}

// fxpLstatPkt is used to request a file/directory's attributes.
// Symlinks are NOT followed, i.e. statting a symlink returns
// info on the symlink itself.
type fxpLstatPkt struct {
	ID   uint32
	Path string
}

func (p *fxpLstatPkt) id() uint32 { return p.ID }

func (p *fxpLstatPkt) MarshalBinary() ([]byte, error) {
	return marshalIDString(ssh_FXP_LSTAT, p.ID, p.Path)
}

func (p *fxpLstatPkt) UnmarshalBinary(b []byte) error {
	return unmarshalIDString(b, &p.ID, &p.Path)
}

// fxpFstatPkt is used to request an OPEN file's attributes.
// The provided handle must be a valid file handle returned
// from SSH_FXP_OPEN (not a directory handle).
type fxpFstatPkt struct {
	ID     uint32
	Handle string
}

func (p *fxpFstatPkt) id() uint32 { return p.ID }

func (p *fxpFstatPkt) MarshalBinary() ([]byte, error) {
	return marshalIDString(ssh_FXP_FSTAT, p.ID, p.Handle)
}

func (p *fxpFstatPkt) UnmarshalBinary(b []byte) error {
	return unmarshalIDString(b, &p.ID, &p.Handle)
}

type fxpSetstatPkt struct {
	ID   uint32
	Path string
	Attr *FileAttr
}

func (p *fxpSetstatPkt) id() uint32 { return p.ID }

func (p *fxpSetstatPkt) MarshalBinary() ([]byte, error) {
	return marshalIDStringAttr(ssh_FXP_SETSTAT, p.ID, p.Path, p.Attr)
}

func (p *fxpSetstatPkt) UnmarshalBinary(b []byte) error {
	return unmarshalIDStringAttr(b, &p.ID, &p.Path, &p.Attr)
}

type fxpFsetstatPkt struct {
	ID     uint32
	Handle string
	Attr   *FileAttr
}

func (p *fxpFsetstatPkt) id() uint32 { return p.ID }

func (p *fxpFsetstatPkt) MarshalBinary() ([]byte, error) {
	return marshalIDStringAttr(ssh_FXP_FSETSTAT, p.ID, p.Handle, p.Attr)
}

func (p *fxpFsetstatPkt) UnmarshalBinary(b []byte) error {
	return unmarshalIDStringAttr(b, &p.ID, &p.Handle, &p.Attr)
}

type fxpReadlinkPkt struct {
	ID   uint32
	Path string
}

func (p *fxpReadlinkPkt) id() uint32 { return p.ID }

func (p *fxpReadlinkPkt) MarshalBinary() ([]byte, error) {
	return marshalIDString(ssh_FXP_READLINK, p.ID, p.Path)
}

func (p *fxpReadlinkPkt) UnmarshalBinary(b []byte) error {
	return unmarshalIDString(b, &p.ID, &p.Path)
}

type fxpSymlinkPkt struct {
	ID         uint32
	LinkPath   string
	TargetPath string
}

func (p *fxpSymlinkPkt) id() uint32 { return p.ID }

func (p *fxpSymlinkPkt) MarshalBinary() ([]byte, error) {
	b := allocPkt(ssh_FXP_SYMLINK, 4+(4+len(p.LinkPath))+(4+len(p.TargetPath)))
	b = marshalUint32(b, p.ID)
	b = marshalString(b, p.Targetpath)
	return marshalString(b, p.Linkpath), nil
}

func (p *fxpSymlinkPkt) UnmarshalBinary(b []byte) (err error) {
	if p.ID, b, err = unmarshalUint32Safe(b); err != nil {
		return
	}
	if p.Linkpath, b, err = unmarshalStringSafe(b); err != nil {
		return
	}
	p.Targetpath, _, err = unmarshalStringSafe(b)
	return
}

type fxpRealpathPkt struct {
	ID   uint32
	Path string
}

func (p *fxpRealpathPkt) id() uint32 { return p.ID }

func (p *fxpRealpathPkt) MarshalBinary() ([]byte, error) {
	return marshalIDString(ssh_FXP_REALPATH, p.ID, p.Path)
}

func (p *fxpRealpathPkt) UnmarshalBinary(b []byte) error {
	return unmarshalIDString(b, &p.ID, &p.Path)
}

// SERVER -> CLIENT PACKETS

type fxpStatusPkt struct {
	ID uint32
	StatusError
}

func (p *fxpStatusPkt) id() uint32 { return p.ID }

func (p *fxpStatusPkt) MarshalBinary() ([]byte, error) {
	b := allocPkt(ssh_FXP_STATUS, 4+4+(4+len(p.msg))+(4+len(p.lang)))
	b = marshalUint32(b, p.ID)
	b = marshalUint32(b, p.Code)
	b = marshalString(b, p.msg)
	return marshalString(b, p.lang), nil
}

func (p *fxpStatusPkt) UnmarshalBinary(b []byte) (err error) {
	if p.ID, b, err = unmarshalUint32Safe(b); err != nil {
		return
	}
	if p.Code, b, err = unmarshalUint32Safe(b); err != nil {
		return
	}
	if p.msg, b, err = unmarshalStringSafe(b); err != nil {
		return
	}
	p.lang, _, err = unmarshalStringSafe(b)
	return
}

type fxpHandlePkt struct {
	ID     uint32
	Handle string // must not exceed 256 bytes, per the spec
}

func (p *fxpHandlePkt) id() uint32 { return p.ID }

func (p *fxpHandlePkt) MarshalBinary() ([]byte, error) {
	return marshalIDString(ssh_FXP_HANDLE, p.ID, p.Handle)
}

func (p *fxpHandlePkt) UnmarshalBinary(b []byte) error {
	return unmarshalIDString(b, &p.ID, &p.Handle)
}

type fxpDataPkt struct {
	ID   uint32
	Data []byte
}

func (p *fxpDataPkt) id() uint32 { return p.ID }

func (p *fxpDataPkt) MarshalBinary() ([]byte, error) {
	b := allocPkt(ssh_FXP_DATA, 4+(4+len(p.Data)))
	b = marshalUint32(b, p.ID)
	b = marshalUint32(b, p.Length)
	return append(b, p.Data...), nil
}

func (p *fxpDataPkt) UnmarshalBinary(b []byte) (err error) {
	if p.ID, b, err = unmarshalUint32Safe(b); err != nil {
		return
	}

	var dataLen uint32
	if dataLen, b, err = unmarshalUint32Safe(b); err != nil {
		return
	}
	if len(b) < dataLen {
		return errShortPacket
	}
	p.Data = b[:dataLen]

	return
}

type fxpNamePkt struct {
	ID    uint32
	Items []fxpNamePktItem
}

type fxpNamePktItem struct {
	Name string // relative path for SSH_FXP_READDIR, absolute for SSH_FXP_REALPATH

	// Detailed human-readable info for directory listing. The spec does not actually
	// specify an exact format, but recommends the output of $(ls -l) as a reference.
	LongName string

	Attr *FileAttr
}

func (p *fxpNamePkt) id() uint32 { return p.ID }

func (p *fxpNamePkt) MarshalBinary() ([]byte, error) {
	// Compute packet data length (not including length or type prefix)
	pktLen := 4 // uint32 ID
	for _, item := range p.Items {
		dataLen += (4 + len(item.Name)) + (4 + len(item.LongName)) + item.Attr.encodedSize()
	}

	b := allocPkt(ssh_FXP_NAME, pktLen)
	b = marshalUint32(b, p.ID)
	b = marshalUint32(b, len(p.Items))
	for _, item := range p.Items {
		b = marshalString(b, item.Name)
		b = marshalString(b, item.LongName)
		b = marshalFileAttr(b, item.Attr)
	}

	return b, nil
}

func (p *fxpNamePkt) UnmarshalBinary(b []byte) (err error) {
	if p.ID, b, err = unmarshalUint32Safe(b); err != nil {
		return
	}

	var count uint32
	if count, b, err = unmarshalUint32Safe(b); err != nil {
		return
	}

	p.Items = make([]fxpNamePktItem, count)
	for i := uint32(0); i < count; i++ {
		if p.Items[i].Name, b, err = unmarshalStringSafe(b); err != nil {
			return
		}
		if p.Items[i].LongName, b, err = unmarshalStringSafe(b); err != nil {
			return
		}
		if p.Items[i].Attr, b, err = unmarshalFileAttrSafe(b); err != nil {
			return
		}
	}

	return
}

type fxpAttrPkt struct {
	ID   uint32
	Attr *FileAttr
}

func (p *fxpAttrPkt) id() uint32 { return p.ID }

func (p *fxpAttrPkt) MarshalBinary() ([]byte, error) {
	b := allocPkt(ssh_FXP_ATTRS, 4+p.Attr.encodedSize())
	b = marshalUint32(b, p.ID)
	return marshalFileAttr(b, p.Attr), nil
}

func (p *fxpAttrPkt) UnmarshalBinary(b []byte) (err error) {
	if p.ID, b, err = unmarshalUint32Safe(b); err != nil {
		return
	}
	p.Attr, _, err = unmarshalFileAttrSafe(b)
	return
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
