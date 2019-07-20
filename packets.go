package sftp

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

type extensionPair struct {
	Name string
	Data string
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

// fxpSymlinkPkt is a request to create a symlink.
//
// The OpenSSH creators screwed up when implementing SSH_FXP_SYMLINK and
// reversed the 'LinkPath' and 'TargetPath' fields, and the widespread
// influence of the library forced many clients and servers to follow suit.
// User code MUST be allowed to tell this library how to interpret the two
// paths:
//
//		1. According to the spec: Path1 is the link and Path2 is the target
//		2. According to OpenSSH: Path1 is the target and Path2 is the link
//
type fxpSymlinkPkt struct {
	FollowSpec bool
	ID         uint32
	LinkPath   string
	TargetPath string
}

func (p *fxpSymlinkPkt) id() uint32 { return p.ID }

func (p *fxpSymlinkPkt) MarshalBinary() ([]byte, error) {
	b := allocPkt(ssh_FXP_SYMLINK, 4+(4+len(p.LinkPath))+(4+len(p.TargetPath)))
	b = marshalUint32(b, p.ID)

	if p.FollowSpec {
		b = marshalString(b, p.LinkPath)
		return nil, marshalString(b, p.TargetPath)
	}
	// Otherwise follow OpenSSH (reverse order)
	b = marshalString(b, p.TargetPath)
	return marshalString(b, p.LinkPath), nil
}

func (p *fxpSymlinkPkt) UnmarshalBinary(b []byte) (err error) {
	if p.ID, b, err = unmarshalUint32Safe(b); err != nil {
		return
	}
	if p.Path1, b, err = unmarshalStringSafe(b); err != nil {
		return
	}
	p.Path2, _, err = unmarshalStringSafe(b)
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

// fxpExtendedPkt is the overarching shape of extended request packets. It does
// not implement encoding.BinaryMarshaler because the specific extended packet
// types should be able to marshal themselves completely (i.e. including an
// SSH_FXP_EXTENDED byte).
type fxpExtendedPkt struct {
	ID          uint32
	RequestName string
	RequestData []byte
}

func (p *fxpExtendedPkt) UnmarshalBinary(b []byte) (err error) {
	if p.ID, b, err = unmarshalUint32Safe(b); err != nil {
		return
	}
	p.RequestName, p.RequestData, err = unmarshalStringSafe(b)
	return
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

// fxpExtendedReplyPkt is the overarching shape of extended reply packets. It
// does not implement encoding.BinaryMarshaler because the specific extended
// packet types should be able to marshal themselves completely (i.e. including
// an SSH_FXP_EXTENDED_REPLY byte).
type fxpExtendedReplyPkt struct {
	ID   uint32
	Data []byte
}

func (p *fxpExtendedReplyPkt) UnmarshalBinary(b []byte) (err error) {
	p.ID, p.Data, err = unmarshalUint32Safe(b)
	return
}
