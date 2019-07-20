package sftp

import (
	"encoding"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"time"
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
