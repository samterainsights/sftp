package sftp

import (
	"context"
	"io"
	"os"
	"path"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/pkg/errors"
)

// maxReadWriteSize is the maximum number of bytes which may be transferred in
// a single SSH_FXP_READ or SSH_FXP_WRITE packet.
const maxReadWriteSize = 1 << 15

// MaxReaddirItems is the maximum number of files to return for a single
// SSH_FXP_READDIR request.
const MaxReaddirItems = 100

var errNoSuchHandle = errors.New("invalid handle")

// A FileHandle is an TODO(samterainsights)
type FileHandle interface {
	os.FileInfo
	io.ReaderAt
	io.WriterAt
	io.Closer

	Setstat(*FileAttr) error
}

// DirReader is the interface that wraps the basic ReadEntries method.
//
// ReadEntries reads the contents of the associated directory, returning
// information identical to what would be returned by calling Lstat for
// each of the child paths.
//
// ReadEntries attempts to read len(dst) entries from the directory,
// returning the number of entries copied and a non-nil error if
// copied < len(dst). Should return io.EOF if there are simply no more
// entries left.
type DirReader interface {
	ReadEntries(dst []os.FileInfo) (copied int, err error)
}

// RequestHandler is responsible for handling the various kinds of SFTP requests.
// Two implementations are provided by this library: an in-memory filesystem and
// a wrapper around the OS filesystem. All paths are cleaned before being passed
// to a RequestHandler.
type RequestHandler interface {
	// OpenFile should behave identically to os.OpenFile.
	OpenFile(string, int, os.FileMode) (FileHandle, error)

	// Mkdir creates a new directory. An error should be returned if the specified
	// path already exists.
	Mkdir(string, *FileAttr) error

	// OpenDir opens a directory for scanning. An error should be returned if the
	// given path is not a directory. If the returned DirReader can be cast to an
	// io.Closer, its Close method will be called once the SFTP client is done
	// scanning.
	OpenDir(string) (DirReader, error)

	// Rename renames the given path. An error should be returned if the path does
	// not exist or the new path already exists.
	Rename(path, to string) error

	// Stat retrieves info about the given path, following symlinks.
	Stat(string) (os.FileInfo, error)

	// Lstat retrieves info about the given path, and does not follow symlinks,
	// i.e. it can return information about symlinks themselves.
	Lstat(string) (os.FileInfo, error)

	// Setstat set attributes for the given path.
	Setstat(string, *FileAttr) error

	// Symlink creates a symlink with the given target.
	Symlink(path, target string) error

	// ReadLink returns the target path of the given symbolic link.
	ReadLink(string) (string, error)

	// Rmdir removes the specified directory. An error should be returned if the
	// given path does not exists, is not a directory, or has children.
	Rmdir(string) error

	// Remove removes the specified file. An error should be returned if the path
	// does not exist or it is a directory.
	Remove(string) error

	// RealPath is responsible for producing an absolute path from a relative one.
	RealPath(string) (string, error)
}

// server abstracts the sftp protocol with an http request-like protocol
type server struct {
	io.ReadWriter
	RequestHandler

	pktMgr       *packetManager
	openFiles    map[string]FileHandle
	openFilesMtx sync.RWMutex
	openDirs     map[string]DirReader
	openDirsMtx  sync.RWMutex
	handleCtr    uint32
}

// Serve the SFTP protocol over a connection. Generally you will want to serve it on top
// of an SSH "session" channel, however it could also be served over TLS, etc. Note that
// SFTP has no security provisions so it should always be layered on top of a secure
// connection.
func Serve(transport io.ReadWriter, handler RequestHandler) (err error) {
	s := &server{
		ReadWriter:     transport,
		RequestHandler: handler,
		pktMgr:         newPktMgr(transport),
		openFiles:      make(map[string]FileHandle),
		openDirs:       make(map[string]DirReader),
	}
	defer s.closeAllHandles()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup

	pktChan := s.pktMgr.workerChan(func(ch chan orderedRequest) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := s.packetWorker(ctx, ch); err != nil {
				// FIXME(samterainsights): propagate error
			}
		}()
	})

	defer wg.Wait()
	defer close(pktChan)

	var pktType uint8
	var pktBytes []byte
	for {
		if pktType, pktBytes, err = readPacket(transport); err != nil {
			return
		}

		var pkt requestPacket
		if pkt, err = makePacket(fxp(pktType), pktBytes); err != nil {
			switch errors.Cause(err) {
			case errUnknownExtendedPacket:
				if err := s.replyError(pkt, ErrOpUnsupported); err != nil {
					debug("failed to send err packet: %v", err)
					// FIXME(samterainsights): propagate error
					break
				}
			default:
				debug("makePacket err: %v", err)
				// FIXME(samterainsights): propagate error
				break
			}
		}

		pktChan <- s.pktMgr.newOrderedRequest(pkt)
	}
}

func (s *server) packetWorker(ctx context.Context, pktChan chan orderedRequest) error {
	for pkt := range pktChan {
		var rpkt responsePacket
		switch pkt := pkt.requestPacket.(type) {
		case *fxpInitPkt:
			rpkt = &fxpVersionPkt{Version: ProtocolVersion}

		case *fxpOpenPkt:
			if f, err := s.OpenFile(path.Clean(pkt.Path), pkt.PFlags.os(), pkt.Attr.Perms); err != nil {
				rpkt = statusFromError(pkt, err)
			} else {
				handle := s.nextHandle()
				s.openFilesMtx.Lock()
				s.openFiles[handle] = f
				s.openFilesMtx.Unlock()
				rpkt = &fxpHandlePkt{pkt.ID, handle}
			}

		case *fxpClosePkt:
			err := s.closeFile(pkt.Handle)
			if err == errNoSuchHandle {
				err = s.closeDir(pkt.Handle)
			}
			rpkt = statusFromError(pkt, err)

		case *fxpReadPkt:
			if f, err := s.getFile(pkt.Handle); err != nil {
				rpkt = statusFromError(pkt, err)
			} else {
				data := make([]byte, clamp(pkt.Len, maxReadWriteSize))
				n, err := f.ReadAt(data, int64(pkt.Offset))

				if err != nil && (err != io.EOF || n == 0) {
					rpkt = statusFromError(pkt, err)
				} else {
					rpkt = &fxpDataPkt{pkt.ID, data[:n]}
				}
			}

		case *fxpWritePkt:
			if f, err := s.getFile(pkt.Handle); err != nil {
				rpkt = statusFromError(pkt, err)
			} else {
				_, err = f.WriteAt(pkt.Data, int64(pkt.Offset))
				rpkt = statusFromError(pkt, err)
			}

		case *fxpStatPkt:
			if info, err := s.Stat(path.Clean(pkt.Path)); err != nil {
				rpkt = statusFromError(pkt, err)
			} else {
				rpkt = &fxpAttrPkt{
					pkt.ID,
					fileAttrFromInfo(info),
				}
			}

		case *fxpLstatPkt:
			if info, err := s.Lstat(path.Clean(pkt.Path)); err != nil {
				rpkt = statusFromError(pkt, err)
			} else {
				rpkt = &fxpAttrPkt{
					pkt.ID,
					fileAttrFromInfo(info),
				}
			}

		case *fxpFstatPkt:
			if f, err := s.getFile(pkt.Handle); err != nil {
				rpkt = statusFromError(pkt, err)
			} else {
				rpkt = &fxpAttrPkt{
					pkt.ID,
					fileAttrFromInfo(f),
				}
			}

		case *fxpSetstatPkt:
			rpkt = statusFromError(pkt, s.Setstat(path.Clean(pkt.Path), pkt.Attr))

		case *fxpFsetstatPkt:
			if f, err := s.getFile(pkt.Handle); err != nil {
				rpkt = statusFromError(pkt, err)
			} else {
				rpkt = statusFromError(pkt, f.Setstat(pkt.Attr))
			}

		case *fxpOpendirPkt:
			if d, err := s.OpenDir(path.Clean(pkt.Path)); err != nil {
				rpkt = statusFromError(pkt, err)
			} else {
				handle := s.nextHandle()
				s.openDirsMtx.Lock()
				s.openDirs[handle] = d
				s.openDirsMtx.Unlock()
				rpkt = &fxpHandlePkt{pkt.ID, handle}
			}

		case *fxpReaddirPkt:
			if d, err := s.getDir(pkt.Handle); err != nil {
				rpkt = statusFromError(pkt, err)
			} else {
				files := make([]os.FileInfo, MaxReaddirItems)
				if n, err := d.ReadEntries(files); n > 0 {
					items := make([]fxpNamePktItem, n)
					for i, f := range files[:n] {
						name := f.Name()
						items[i].Name = name
						items[i].LongName = name
						items[i].Attr = fileAttrFromInfo(f)
					}
					rpkt = &fxpNamePkt{pkt.ID, items}
				} else {
					rpkt = statusFromError(pkt, err)
				}
			}

		case *fxpRemovePkt:
			rpkt = statusFromError(pkt, s.Remove(path.Clean(pkt.Path)))

		case *fxpMkdirPkt:
			rpkt = statusFromError(pkt, s.Mkdir(path.Clean(pkt.Path), pkt.Attr))

		case *fxpRmdirPkt:
			rpkt = statusFromError(pkt, s.Rmdir(path.Clean(pkt.Path)))

		case *fxpRealpathPkt:
			if fpath := path.Clean(pkt.Path); path.IsAbs(fpath) {
				rpkt = &fxpNamePkt{
					ID: pkt.ID,
					Items: []fxpNamePktItem{{
						Name:     fpath,
						LongName: fpath,
						Attr:     &FileAttr{},
					}},
				}
			} else if abs, err := s.RealPath(fpath); err != nil {
				rpkt = statusFromError(pkt, err)
			} else {
				rpkt = &fxpNamePkt{
					pkt.ID,
					[]fxpNamePktItem{{abs, abs, &FileAttr{}}},
				}
			}

		case *fxpRenamePkt:
			rpkt = statusFromError(pkt, s.Rename(
				path.Clean(pkt.OldPath),
				path.Clean(pkt.NewPath),
			))

		case *fxpReadlinkPkt:
			if fpath, err := s.ReadLink(path.Clean(pkt.Path)); err != nil {
				rpkt = statusFromError(pkt, err)
			} else {
				rpkt = &fxpNamePkt{
					pkt.ID,
					[]fxpNamePktItem{{fpath, fpath, &FileAttr{}}},
				}
			}

		case *fxpSymlinkPkt:
			rpkt = statusFromError(pkt, s.Symlink(
				path.Clean(pkt.LinkPath),
				path.Clean(pkt.TargetPath),
			))

		default:
			rpkt = statusFromError(pkt, ErrOpUnsupported)
		}

		s.pktMgr.readyPacket(orderedResponse{rpkt, pkt.orderID()})
	}
	return nil
}

func (s *server) replyError(pkt requestPacket, err error) error {
	b, err := statusFromError(pkt, err).MarshalBinary()
	if err != nil {
		return err
	}
	_, err = s.Write(b)
	return err
}

func clamp(v, max uint32) uint32 {
	if v > max {
		return max
	}
	return v
}

func (s *server) nextHandle() string {
	handle := atomic.AddUint32(&s.handleCtr, 1)
	return strconv.FormatUint(uint64(handle), 36)
}

func (s *server) getFile(handle string) (FileHandle, error) {
	s.openFilesMtx.RLock()
	defer s.openFilesMtx.RUnlock()
	if f, exists := s.openFiles[handle]; exists {
		return f, nil
	}
	return nil, errNoSuchHandle
}

func (s *server) closeFile(handle string) error {
	s.openFilesMtx.Lock()
	defer s.openFilesMtx.Unlock()
	if f, exists := s.openFiles[handle]; exists {
		delete(s.openFiles, handle)
		return f.Close()
	}
	return errNoSuchHandle
}

func (s *server) getDir(handle string) (DirReader, error) {
	s.openDirsMtx.RLock()
	defer s.openDirsMtx.RUnlock()
	if d, exists := s.openDirs[handle]; exists {
		return d, nil
	}
	return nil, errNoSuchHandle
}

func (s *server) closeDir(handle string) error {
	s.openDirsMtx.Lock()
	defer s.openDirsMtx.Unlock()
	if d, exists := s.openDirs[handle]; exists {
		delete(s.openDirs, handle)
		if closer, ok := d.(io.Closer); ok {
			return closer.Close()
		}
		return nil
	}
	return errNoSuchHandle
}

// closeAllHandles closes all open file/directory handles.
func (s *server) closeAllHandles() {
	s.openFilesMtx.Lock()
	for handle, file := range s.openFiles {
		file.Close() // TODO(samterainsights): propagate error somehow
		delete(s.openFiles, handle)
	}
	s.openFilesMtx.Unlock()

	s.openDirsMtx.Lock()
	for handle, dir := range s.openDirs {
		if closer, ok := dir.(io.Closer); ok {
			closer.Close() // TODO(samterainsights): propagate error somehow
		}
		delete(s.openDirs, handle)
	}
	s.openDirsMtx.Unlock()
}
