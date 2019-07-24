package sftp

// Here lies the definition of packets along with their encoding.BinaryMarshaler/Unmarshaler implementations.
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

// TODO(samterainsights): eliminate the need for this fake method. Currently needed
// to satisfy the ider/responsePacket interfaces because all packets are treated in
// the same way even though the init/version packets are only sent in a handshake at
// the beginning.
func (p *fxpInitPkt) id() uint32 { return 0 }

func (p *fxpInitPkt) MarshalBinary() ([]byte, error) {
	dataLen := 4 // uint32 version
	for _, ext := range p.Extensions {
		dataLen += (4 + len(ext.Name)) + (4 + len(ext.Data)) // string + string
	}
	b := allocPkt(fxpInit, dataLen)
	b = appendU32(b, p.Version)
	for _, ext := range p.Extensions {
		b = appendStr(b, ext.Name)
		b = appendStr(b, ext.Data)
	}
	return b, nil
}

func (p *fxpInitPkt) UnmarshalBinary(b []byte) (err error) {
	if p.Version, b, err = takeU32(b); err != nil {
		return
	}
	for len(b) > 0 {
		var ext extensionPair
		if ext.Name, b, err = takeStr(b); err != nil {
			return
		}
		if ext.Data, b, err = takeStr(b); err != nil {
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

// TODO(samterainsights): eliminate the need for this fake method. Currently needed
// to satisfy the ider/responsePacket interfaces because all packets are treated in
// the same way even though the init/version packets are only sent in a handshake at
// the beginning.
func (p *fxpVersionPkt) id() uint32 { return 0 }

func (p *fxpVersionPkt) MarshalBinary() ([]byte, error) {
	dataLen := 4 // uint32 version
	for _, ext := range p.Extensions {
		dataLen += (4 + len(ext.Name)) + (4 + len(ext.Data)) // string + string
	}
	b := allocPkt(fxpVersion, dataLen)
	b = appendU32(b, p.Version)
	for _, ext := range p.Extensions {
		b = appendStr(b, ext.Name)
		b = appendStr(b, ext.Data)
	}
	return b, nil
}

func (p *fxpVersionPkt) UnmarshalBinary(b []byte) (err error) {
	if p.Version, b, err = takeU32(b); err != nil {
		return
	}
	for len(b) > 0 {
		var ext extensionPair
		if ext.Name, b, err = takeStr(b); err != nil {
			return
		}
		if ext.Data, b, err = takeStr(b); err != nil {
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
	b := allocPkt(fxpOpen, 4+(4+len(p.Path))+4+p.Attr.encodedSize())
	b = appendU32(b, p.ID)
	b = appendStr(b, p.Path)
	b = appendU32(b, uint32(p.PFlags))
	b = appendAttr(b, p.Attr)
	return b, nil
}

func (p *fxpOpenPkt) UnmarshalBinary(b []byte) (err error) {
	if p.ID, b, err = takeU32(b); err != nil {
		return
	}
	if p.Path, b, err = takeStr(b); err != nil {
		return
	}

	var pflags uint32
	if pflags, b, err = takeU32(b); err != nil {
		return
	}
	p.PFlags = pflag(pflags)

	if p.Attr, b, err = takeAttr(b); err != nil {
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
	return marshalIDString(fxpClose, p.ID, p.Handle)
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
	b := allocPkt(fxpRead, 4+(4+len(p.Handle))+8+4)
	b = appendU32(b, p.ID)
	b = appendStr(b, p.Handle)
	b = appendU64(b, p.Offset)
	b = appendU32(b, p.Len)
	return b, nil
}

func (p *fxpReadPkt) UnmarshalBinary(b []byte) (err error) {
	if p.ID, b, err = takeU32(b); err != nil {
		return
	}
	if p.Handle, b, err = takeStr(b); err != nil {
		return
	}
	if p.Offset, b, err = takeU64(b); err != nil {
		return
	}
	if p.Len, _, err = takeU32(b); err != nil {
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
	b := allocPkt(fxpWrite, 4+(4+len(p.Handle))+8+(4+len(p.Data)))
	b = appendU32(b, p.ID)
	b = appendStr(b, p.Handle)
	b = appendU64(b, p.Offset)
	b = appendU32(b, uint32(len(p.Data)))
	b = append(b, p.Data...)
	return b, nil
}

func (p *fxpWritePkt) UnmarshalBinary(b []byte) (err error) {
	if p.ID, b, err = takeU32(b); err != nil {
		return
	}
	if p.Handle, b, err = takeStr(b); err != nil {
		return
	}
	if p.Offset, b, err = takeU64(b); err != nil {
		return
	}

	var dataLen uint32
	if dataLen, b, err = takeU32(b); err != nil {
		return
	}
	if uint32(len(b)) < dataLen {
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
	return marshalIDString(fxpRemove, p.ID, p.Path)
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
	b := allocPkt(fxpRename, 4+(4+len(p.OldPath))+(4+len(p.NewPath)))
	b = appendU32(b, p.ID)
	b = appendStr(b, p.OldPath)
	b = appendStr(b, p.NewPath)
	return b, nil
}

func (p *fxpRenamePkt) UnmarshalBinary(b []byte) (err error) {
	if p.ID, b, err = takeU32(b); err != nil {
		return
	}
	if p.OldPath, b, err = takeStr(b); err != nil {
		return
	}
	p.NewPath, _, err = takeStr(b)
	return
}

type fxpMkdirPkt struct {
	ID   uint32
	Path string
	Attr *FileAttr
}

func (p *fxpMkdirPkt) id() uint32 { return p.ID }

func (p *fxpMkdirPkt) MarshalBinary() ([]byte, error) {
	return marshalIDStringAttr(fxpMkdir, p.ID, p.Path, p.Attr)
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
	return marshalIDString(fxpRmdir, p.ID, p.Path)
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
	return marshalIDString(fxpOpendir, p.ID, p.Path)
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
	return marshalIDString(fxpReaddir, p.ID, p.Handle)
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
	return marshalIDString(fxpStat, p.ID, p.Path)
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
	return marshalIDString(fxpLstat, p.ID, p.Path)
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
	return marshalIDString(fxpFstat, p.ID, p.Handle)
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
	return marshalIDStringAttr(fxpSetstat, p.ID, p.Path, p.Attr)
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
	return marshalIDStringAttr(fxpFsetstat, p.ID, p.Handle, p.Attr)
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
	return marshalIDString(fxpReadlink, p.ID, p.Path)
}

func (p *fxpReadlinkPkt) UnmarshalBinary(b []byte) error {
	return unmarshalIDString(b, &p.ID, &p.Path)
}

// fxpSymlinkPkt is a request to create a symlink.
//
// The OpenSSH creators screwed up when implementing SSH_FXP_SYMLINK and
// reversed the 'LinkPath' and 'TargetPath' fields, and the widespread
// influence of the library forced many clients and servers to follow suit.
// User code MUST be allowed to tell this library how to decode the paths:
//
//		1. According to the spec: link comes first, then target
//		2. According to OpenSSH: target comes first, then link
//
type fxpSymlinkPkt struct {
	FollowSpec bool
	ID         uint32
	LinkPath   string
	TargetPath string
}

func (p *fxpSymlinkPkt) id() uint32 { return p.ID }

func (p *fxpSymlinkPkt) MarshalBinary() ([]byte, error) {
	b := allocPkt(fxpSymlink, 4+(4+len(p.LinkPath))+(4+len(p.TargetPath)))
	b = appendU32(b, p.ID)

	if p.FollowSpec {
		b = appendStr(b, p.LinkPath)
		return appendStr(b, p.TargetPath), nil
	}
	// Otherwise follow OpenSSH (reverse order)
	b = appendStr(b, p.TargetPath)
	return appendStr(b, p.LinkPath), nil
}

func (p *fxpSymlinkPkt) UnmarshalBinary(b []byte) (err error) {
	if p.ID, b, err = takeU32(b); err != nil {
		return
	}
	if p.FollowSpec {
		if p.LinkPath, b, err = takeStr(b); err != nil {
			return
		}
		p.TargetPath, _, err = takeStr(b)
		return
	}
	if p.TargetPath, b, err = takeStr(b); err != nil {
		return
	}
	p.LinkPath, _, err = takeStr(b)
	return
}

type fxpRealpathPkt struct {
	ID   uint32
	Path string
}

func (p *fxpRealpathPkt) id() uint32 { return p.ID }

func (p *fxpRealpathPkt) MarshalBinary() ([]byte, error) {
	return marshalIDString(fxpRealpath, p.ID, p.Path)
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

func (p *fxpExtendedPkt) id() uint32 { return p.ID }

func (p *fxpExtendedPkt) UnmarshalBinary(b []byte) (err error) {
	if p.ID, b, err = takeU32(b); err != nil {
		return
	}
	p.RequestName, p.RequestData, err = takeStr(b)
	return
}

// SERVER -> CLIENT PACKETS

type fxpStatusPkt struct {
	ID uint32
	StatusError
}

func (p *fxpStatusPkt) id() uint32 { return p.ID }

func (p *fxpStatusPkt) MarshalBinary() ([]byte, error) {
	b := allocPkt(fxpStatus, 4+4+(4+len(p.msg))+(4+len(p.lang)))
	b = appendU32(b, p.ID)
	b = appendU32(b, p.Code)
	b = appendStr(b, p.msg)
	return appendStr(b, p.lang), nil
}

func (p *fxpStatusPkt) UnmarshalBinary(b []byte) (err error) {
	if p.ID, b, err = takeU32(b); err != nil {
		return
	}
	if p.Code, b, err = takeU32(b); err != nil {
		return
	}
	if p.msg, b, err = takeStr(b); err != nil {
		return
	}
	p.lang, _, err = takeStr(b)
	return
}

type fxpHandlePkt struct {
	ID     uint32
	Handle string // must not exceed 256 bytes, per the spec
}

func (p *fxpHandlePkt) id() uint32 { return p.ID }

func (p *fxpHandlePkt) MarshalBinary() ([]byte, error) {
	return marshalIDString(fxpHandle, p.ID, p.Handle)
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
	b := allocPkt(fxpData, 4+(4+len(p.Data)))
	b = appendU32(b, p.ID)
	b = appendU32(b, uint32(len(p.Data)))
	return append(b, p.Data...), nil
}

func (p *fxpDataPkt) UnmarshalBinary(b []byte) (err error) {
	if p.ID, b, err = takeU32(b); err != nil {
		return
	}

	var dataLen uint32
	if dataLen, b, err = takeU32(b); err != nil {
		return
	}
	if uint32(len(b)) < dataLen {
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
	dataLen := 4 // uint32 ID
	for _, item := range p.Items {
		dataLen += (4 + len(item.Name)) + (4 + len(item.LongName)) + item.Attr.encodedSize()
	}

	b := allocPkt(fxpName, dataLen)
	b = appendU32(b, p.ID)
	b = appendU32(b, uint32(len(p.Items)))
	for _, item := range p.Items {
		b = appendStr(b, item.Name)
		b = appendStr(b, item.LongName)
		b = appendAttr(b, item.Attr)
	}

	return b, nil
}

func (p *fxpNamePkt) UnmarshalBinary(b []byte) (err error) {
	if p.ID, b, err = takeU32(b); err != nil {
		return
	}

	var count uint32
	if count, b, err = takeU32(b); err != nil {
		return
	}

	p.Items = make([]fxpNamePktItem, count)
	for i := uint32(0); i < count; i++ {
		if p.Items[i].Name, b, err = takeStr(b); err != nil {
			return
		}
		if p.Items[i].LongName, b, err = takeStr(b); err != nil {
			return
		}
		if p.Items[i].Attr, b, err = takeAttr(b); err != nil {
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
	b := allocPkt(fxpAttrs, 4+p.Attr.encodedSize())
	b = appendU32(b, p.ID)
	return appendAttr(b, p.Attr), nil
}

func (p *fxpAttrPkt) UnmarshalBinary(b []byte) (err error) {
	if p.ID, b, err = takeU32(b); err != nil {
		return
	}
	p.Attr, _, err = takeAttr(b)
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
	p.ID, p.Data, err = takeU32(b)
	return
}
