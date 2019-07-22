package sftp

// sftp server counterpart

import (
	"encoding"
	"fmt"
	"io"
	"os"
	"strconv"
	"sync"
	"syscall"

	"github.com/pkg/errors"
)

const sftpServerWorkerCount = 8

// Server is an SSH File Transfer Protocol (sftp) server.
// This is intended to provide the sftp subsystem to an ssh server daemon.
// This implementation currently supports most of sftp server protocol version 3,
// as specified at http://tools.ietf.org/html/draft-ietf-secsh-filexfer-02
type Server struct {
	*conn
	readOnly      bool
	pktMgr        *packetManager
	openFiles     map[string]*os.File
	openFilesLock sync.RWMutex
	handleCount   int
	maxTxPacket   uint32
}

func (svr *Server) nextHandle(f *os.File) string {
	svr.openFilesLock.Lock()
	defer svr.openFilesLock.Unlock()
	svr.handleCount++
	handle := strconv.Itoa(svr.handleCount)
	svr.openFiles[handle] = f
	return handle
}

func (svr *Server) closeHandle(handle string) error {
	svr.openFilesLock.Lock()
	defer svr.openFilesLock.Unlock()
	if f, ok := svr.openFiles[handle]; ok {
		delete(svr.openFiles, handle)
		return f.Close()
	}

	return syscall.EBADF
}

func (svr *Server) getHandle(handle string) (*os.File, bool) {
	svr.openFilesLock.RLock()
	defer svr.openFilesLock.RUnlock()
	f, ok := svr.openFiles[handle]
	return f, ok
}

type serverRespondablePacket interface {
	encoding.BinaryUnmarshaler
	id() uint32
	respond(svr *Server) responsePacket
}

// NewServer creates a new Server instance around the provided streams, serving
// content from the root of the filesystem.
//
// A subsequent call to Serve() is required to begin serving files over SFTP.
func NewServer(rwc io.ReadWriteCloser) (*Server, error) {
	conn := &conn{
		Reader:      rwc,
		WriteCloser: rwc,
	}
	s := &Server{
		conn:        conn,
		pktMgr:      newPktMgr(conn),
		openFiles:   make(map[string]*os.File),
		maxTxPacket: 1 << 15,
	}

	return s, nil
}

// Up to N parallel servers
func (svr *Server) sftpServerWorker(pktChan chan orderedRequest) error {
	for pkt := range pktChan {
		// readonly checks
		readonly := true
		switch pkt := pkt.requestPacket.(type) {
		case notReadOnly:
			readonly = false
		case *fxpOpenPkt:
			readonly = pkt.readonly()
		case *fxpExtendedPkt:
			readonly = pkt.readonly()
		}

		// If server is operating read-only and a write operation is requested,
		// return permission denied
		if !readonly && svr.readOnly {
			svr.sendPacket(orderedResponse{statusFromError(pkt, syscall.EPERM), pkt.orderID()})
			continue
		}

		if err := handlePacket(svr, pkt); err != nil {
			return err
		}
	}
	return nil
}

func handlePacket(s *Server, p orderedRequest) error {
	var rpkt encoding.BinaryMarshaler
	switch p := p.requestPacket.(type) {
	case *fxpInitPkt:
		rpkt = &fxpVersionPkt{Version: sftpProtocolVersion}
	case *fxpStatPkt:
		if info, err := os.Stat(p.Path); err != nil {
			rpkt = statusFromError(p, err)
		} else {
			rpkt = &fxpAttrPkt{
				ID:   p.ID,
				Attr: fileAttrFromInfo(info),
			}
		}
	case *fxpLstatPkt:
		if info, err := os.Lstat(p.Path); err != nil {
			rpkt = statusFromError(p, err)
		} else {
			rpkt = &fxpAttrPkt{
				ID:   p.ID,
				Attr: fileAttrFromInfo(info),
			}
		}
	case *fxpFstatPkt:
		if f, ok := s.getHandle(p.Handle); !ok {
			rpkt = statusFromError(p, syscall.EBADF)
		} else if info, err := f.Stat(); err != nil {
			rpkt = statusFromError(p, err)
		} else {
			rpkt = &fxpAttrPkt{
				ID:   p.ID,
				Attr: fileAttrFromInfo(info),
			}
		}
	case *fxpMkdirPkt:
		// TODO FIXME: ignore flags field
		err := os.Mkdir(p.Path, 0755)
		rpkt = statusFromError(p, err)
	case *fxpRmdirPkt:
		err := os.Remove(p.Path)
		rpkt = statusFromError(p, err)
	case *fxpRemovePkt:
		err := os.Remove(p.Path)
		rpkt = statusFromError(p, err)
	case *fxpRenamePkt:
		err := os.Rename(p.OldPath, p.NewPath)
		rpkt = statusFromError(p, err)
	case *fxpSymlinkPkt:
		err := os.Symlink(p.TargetPath, p.LinkPath)
		rpkt = statusFromError(p, err)
	case *fxpClosePkt:
		rpkt = statusFromError(p, s.closeHandle(p.Handle))
	case *fxpReadlinkPkt:
		f, err := os.Readlink(p.Path)
		rpkt = &fxpNamePkt{
			ID: p.ID,
			Items: []fxpNamePktItem{{
				Name:     f,
				LongName: f,
				// no attributes: https://tools.ietf.org/pdf/draft-ietf-secsh-filexfer-02.pdf#34
			}},
		}
		if err != nil {
			rpkt = statusFromError(p, err)
		}
	case *fxpRealpathPkt:
		rpkt = &fxpStatusPkt{
			ID: p.ID,
			StatusError: StatusError{
				Code: ssh_FX_OP_UNSUPPORTED,
			},
		}
	case *fxpOpendirPkt:
		if stat, err := os.Stat(p.Path); err != nil {
			rpkt = statusFromError(p, err)
		} else if !stat.IsDir() {
			rpkt = statusFromError(p, &os.PathError{
				Path: p.Path, Err: syscall.ENOTDIR})
		} else {
			rpkt = (&fxpOpenPkt{
				ID:     p.ID,
				Path:   p.Path,
				PFlags: PFlagRead,
			}).respond(s)
		}
	case *fxpReadPkt:
		var err error = syscall.EBADF
		f, ok := s.getHandle(p.Handle)
		if ok {
			err = nil
			data := make([]byte, clamp(p.Len, s.maxTxPacket))
			n, _err := f.ReadAt(data, int64(p.Offset))
			if _err != nil && (_err != io.EOF || n == 0) {
				err = _err
			}
			rpkt = &fxpDataPkt{
				ID:   p.ID,
				Data: data[:n],
			}
		}
		if err != nil {
			rpkt = statusFromError(p, err)
		}

	case *fxpWritePkt:
		f, ok := s.getHandle(p.Handle)
		var err error = syscall.EBADF
		if ok {
			_, err = f.WriteAt(p.Data, int64(p.Offset))
		}
		rpkt = statusFromError(p, err)
	case serverRespondablePacket:
		rpkt = p.respond(s)
	default:
		return errors.Errorf("unexpected packet type %T", p)
	}

	s.pktMgr.readyPacket(orderedResponse{rpkt, p.orderID()})
	return nil
}

// Serve serves SFTP connections until the streams stop or the SFTP subsystem
// is stopped.
func (svr *Server) Serve() error {
	var wg sync.WaitGroup
	runWorker := func(ch chan orderedRequest) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := svr.sftpServerWorker(ch); err != nil {
				svr.conn.Close() // shuts down recvPacket
			}
		}()
	}
	pktChan := svr.pktMgr.workerChan(runWorker)

	var err error
	var pkt requestPacket
	var pktType uint8
	var pktBytes []byte
	for {
		pktType, pktBytes, err = svr.recvPacket()
		if err != nil {
			break
		}

		pkt, err = makePacket(fxp(pktType), pktBytes)
		if err != nil {
			switch errors.Cause(err) {
			case errUnknownExtendedPacket:
				if err := svr.sendError(pkt, ErrSshFxOpUnsupported); err != nil {
					debug("failed to send err packet: %v", err)
					svr.conn.Close() // shuts down recvPacket
					break
				}
			default:
				debug("makePacket err: %v", err)
				svr.conn.Close() // shuts down recvPacket
				break
			}
		}

		pktChan <- svr.pktMgr.newOrderedRequest(pkt)
	}

	close(pktChan) // shuts down sftpServerWorkers
	wg.Wait()      // wait for all workers to exit

	// close any still-open files
	for handle, file := range svr.openFiles {
		file.Close()
	}
	return err // error from recvPacket
}

type ider interface {
	id() uint32
}

// The init packet has no ID, so we just return a zero-value ID
func (p fxpInitPkt) id() uint32 { return 0 }

var emptyFileAttr = []interface{}{uint32(0)}

func (p fxpOpenPkt) readonly() bool {
	return !p.hasPflags(PFlagWrite)
}

func (p fxpOpenPkt) hasPflags(flags ...pflag) bool {
	for _, f := range flags {
		if p.PFlags&f == 0 {
			return false
		}
	}
	return true
}

func (p *fxpOpenPkt) respond(svr *Server) responsePacket {
	var osFlags int
	if p.hasPflags(PFlagRead, PFlagWrite) {
		osFlags |= os.O_RDWR
	} else if p.hasPflags(PFlagWrite) {
		osFlags |= os.O_WRONLY
	} else if p.hasPflags(PFlagRead) {
		osFlags |= os.O_RDONLY
	} else {
		// how are they opening?
		return statusFromError(p, syscall.EINVAL)
	}

	if p.hasPflags(PFlagAppend) {
		osFlags |= os.O_APPEND
	}
	if p.hasPflags(PFlagCreate) {
		osFlags |= os.O_CREATE
	}
	if p.hasPflags(PFlagTruncate) {
		osFlags |= os.O_TRUNC
	}
	if p.hasPflags(PFlagExclusive) {
		osFlags |= os.O_EXCL
	}

	f, err := os.OpenFile(p.Path, osFlags, 0644)
	if err != nil {
		return statusFromError(p, err)
	}

	handle := svr.nextHandle(f)
	return &fxpHandlePkt{p.id(), handle}
}

func (p *fxpReaddirPkt) respond(svr *Server) responsePacket {
	f, ok := svr.getHandle(p.Handle)
	if !ok {
		return statusFromError(p, syscall.EBADF)
	}

	dirname := f.Name()
	dirents, err := f.Readdir(128)
	if err != nil {
		return statusFromError(p, err)
	}

	ret := &fxpNamePkt{ID: p.ID}
	for _, dirent := range dirents {
		ret.Items = append(ret.Items, fxpNamePktItem{
			Name:     dirent.Name(),
			LongName: runLs(dirname, dirent),
			Attr:     fileAttrFromInfo(dirent),
		})
	}
	return ret
}

func (p *fxpSetstatPkt) respond(svr *Server) responsePacket {
	attr := p.Attr
	var err error

	debug("setstat name \"%s\"", p.Path)
	if attr.Flags&attrFlagSize != 0 {
		err = os.Truncate(p.Path, int64(attr.Size))
	}
	if err == nil && attr.Flags&attrFlagPermissions != 0 {
		err = os.Chmod(p.Path, attr.Perms)
	}
	if err == nil && attr.Flags&attrFlagAcModTime != 0 {
		err = os.Chtimes(p.Path, attr.AcTime, attr.ModTime)
	}
	if err == nil && attr.Flags&attrFlagUIDGID != 0 {
		err = os.Chown(p.Path, int(attr.UID), int(attr.GID))
	}

	return statusFromError(p, err)
}

func (p *fxpFsetstatPkt) respond(svr *Server) responsePacket {
	f, ok := svr.getHandle(p.Handle)
	if !ok {
		return statusFromError(p, syscall.EBADF)
	}

	attr := p.Attr
	var err error

	debug("fsetstat name \"%s\"", f.Name())
	if attr.Flags&attrFlagSize != 0 {
		err = f.Truncate(int64(attr.Size))
	}
	if err == nil && attr.Flags&attrFlagPermissions != 0 {
		err = f.Chmod(attr.Perms)
	}
	if err == nil && attr.Flags&attrFlagAcModTime != 0 {
		err = os.Chtimes(f.Name(), attr.AcTime, attr.ModTime)
	}
	if err == nil && attr.Flags&attrFlagUIDGID != 0 {
		err = f.Chown(int(attr.UID), int(attr.GID))
	}

	return statusFromError(p, err)
}

// translateErrno translates a syscall error number to a SFTP error code.
func translateErrno(errno syscall.Errno) uint32 {
	switch errno {
	case 0:
		return ssh_FX_OK
	case syscall.ENOENT:
		return ssh_FX_NO_SUCH_FILE
	case syscall.EPERM:
		return ssh_FX_PERMISSION_DENIED
	}

	return ssh_FX_FAILURE
}

func statusFromError(p ider, err error) *fxpStatusPkt {
	ret := &fxpStatusPkt{
		ID: p.id(),
		StatusError: StatusError{
			// ssh_FX_OK                = 0
			// ssh_FX_EOF               = 1
			// ssh_FX_NO_SUCH_FILE      = 2 ENOENT
			// ssh_FX_PERMISSION_DENIED = 3
			// ssh_FX_FAILURE           = 4
			// ssh_FX_BAD_MESSAGE       = 5
			// ssh_FX_NO_CONNECTION     = 6
			// ssh_FX_CONNECTION_LOST   = 7
			// ssh_FX_OP_UNSUPPORTED    = 8
			Code: ssh_FX_OK,
		},
	}
	if err == nil {
		return ret
	}

	debug("statusFromError: error is %T %#v", err, err)
	ret.StatusError.Code = ssh_FX_FAILURE
	ret.StatusError.msg = err.Error()

	switch e := err.(type) {
	case syscall.Errno:
		ret.StatusError.Code = translateErrno(e)
	case *os.PathError:
		debug("statusFromError,pathError: error is %T %#v", e.Err, e.Err)
		if errno, ok := e.Err.(syscall.Errno); ok {
			ret.StatusError.Code = translateErrno(errno)
		}
	case fxerr:
		ret.StatusError.Code = uint32(e)
	default:
		switch e {
		case io.EOF:
			ret.StatusError.Code = ssh_FX_EOF
		case os.ErrNotExist:
			ret.StatusError.Code = ssh_FX_NO_SUCH_FILE
		}
	}

	return ret
}

func clamp(v, max uint32) uint32 {
	if v > max {
		return max
	}
	return v
}

func runLsTypeWord(dirent os.FileInfo) string {
	// find first character, the type char
	// b     Block special file.
	// c     Character special file.
	// d     Directory.
	// l     Symbolic link.
	// s     Socket link.
	// p     FIFO.
	// -     Regular file.
	tc := '-'
	mode := dirent.Mode()
	if (mode & os.ModeDir) != 0 {
		tc = 'd'
	} else if (mode & os.ModeDevice) != 0 {
		tc = 'b'
		if (mode & os.ModeCharDevice) != 0 {
			tc = 'c'
		}
	} else if (mode & os.ModeSymlink) != 0 {
		tc = 'l'
	} else if (mode & os.ModeSocket) != 0 {
		tc = 's'
	} else if (mode & os.ModeNamedPipe) != 0 {
		tc = 'p'
	}

	// owner
	orc := '-'
	if (mode & 0400) != 0 {
		orc = 'r'
	}
	owc := '-'
	if (mode & 0200) != 0 {
		owc = 'w'
	}
	oxc := '-'
	ox := (mode & 0100) != 0
	setuid := (mode & os.ModeSetuid) != 0
	if ox && setuid {
		oxc = 's'
	} else if setuid {
		oxc = 'S'
	} else if ox {
		oxc = 'x'
	}

	// group
	grc := '-'
	if (mode & 040) != 0 {
		grc = 'r'
	}
	gwc := '-'
	if (mode & 020) != 0 {
		gwc = 'w'
	}
	gxc := '-'
	gx := (mode & 010) != 0
	setgid := (mode & os.ModeSetgid) != 0
	if gx && setgid {
		gxc = 's'
	} else if setgid {
		gxc = 'S'
	} else if gx {
		gxc = 'x'
	}

	// all / others
	arc := '-'
	if (mode & 04) != 0 {
		arc = 'r'
	}
	awc := '-'
	if (mode & 02) != 0 {
		awc = 'w'
	}
	axc := '-'
	ax := (mode & 01) != 0
	sticky := (mode & os.ModeSticky) != 0
	if ax && sticky {
		axc = 't'
	} else if sticky {
		axc = 'T'
	} else if ax {
		axc = 'x'
	}

	return fmt.Sprintf("%c%c%c%c%c%c%c%c%c%c", tc, orc, owc, oxc, grc, gwc, gxc, arc, awc, axc)
}
