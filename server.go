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

var maxTxPacket uint32 = 1 << 15
var errNoSuchHandle = errors.New("invalid handle")

// MaxReaddirItems is the maximum number of files to return for a single
// SSH_FXP_READDIR request.
const MaxReaddirItems = 100

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
// a wrapper around the OS filesystem.
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
	*conn
	RequestHandler

	pktMgr       *packetManager
	openFiles    map[string]FileHandle
	openFilesMtx sync.RWMutex
	openDirs     map[string]DirReader
	openDirsMtx  sync.RWMutex
	handleCtr    uint32
}

type noopCloseRWC struct {
	io.ReadWriter
}

func (rwc noopCloseRWC) Close() error { return nil }

// Serve the SFTP protocol over a connection. Generally you will want to serve it on top
// of an SSH "session" channel, however it could also be served over TLS, etc. Note that
// SFTP has no security provisions so it should always be layered on top of a secure
// connection.
func Serve(transport io.ReadWriter, handler RequestHandler) (err error) {
	conn := &conn{
		Reader:      transport,
		WriteCloser: noopCloseRWC{transport},
	}
	rs := &server{
		conn:           conn,
		RequestHandler: handler,
		pktMgr:         newPktMgr(conn),
		openFiles:      make(map[string]FileHandle),
		openDirs:       make(map[string]DirReader),
	}
	defer rs.cleanup()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup

	pktChan := rs.pktMgr.workerChan(func(ch chan orderedRequest) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := rs.packetWorker(ctx, ch); err != nil {
				rs.conn.Close() // shuts down recvPacket
			}
		}()
	})

	defer wg.Wait()
	defer close(pktChan)

	var pktType uint8
	var pktBytes []byte
	for {
		if pktType, pktBytes, err = readPacket(conn); err != nil {
			return
		}

		var pkt requestPacket
		if pkt, err = makePacket(fxp(pktType), pktBytes); err != nil {
			switch errors.Cause(err) {
			case errUnknownExtendedPacket:
				if err := rs.sendError(pkt, ErrSshFxOpUnsupported); err != nil {
					debug("failed to send err packet: %v", err)
					rs.conn.Close() // shuts down recvPacket
					break
				}
			default:
				debug("makePacket err: %v", err)
				rs.conn.Close() // shuts down recvPacket
				break
			}
		}

		pktChan <- rs.pktMgr.newOrderedRequest(pkt)
	}
}

func (rs *server) nextHandle() string {
	handle := atomic.AddUint32(&rs.handleCtr, 1)
	return strconv.FormatUint(uint32(handle), 36)
}

func (rs *server) getFile(handle string) (FileHandle, error) {
	rs.openFilesMtx.RLock()
	defer rs.openFilesMtx.RUnlock()
	if f, exists := rs.openFiles[handle]; exists {
		return f, nil
	}
	return nil, errNoSuchHandle
}

func (rs *server) closeFile(handle string) error {
	rs.openFilesMtx.Lock()
	defer rs.openFilesMtx.Unlock()
	if f, exists := rs.openFiles[handle]; exists {
		delete(rs.openFiles, handle)
		return f.Close()
	}
	return errNoSuchHandle
}

func (rs *server) getDir(handle string) (DirReader, error) {
	rs.openDirsMtx.RLock()
	defer rs.openDirsMtx.RUnlock()
	if d, exists := rs.openDirs[handle]; exists {
		return d, nil
	}
	return nil, errNoSuchHandle
}

func (rs *server) closeDir(handle string) error {
	rs.openDirsMtx.Lock()
	defer rs.openDirsMtx.Unlock()
	if d, exists := rs.openDirs[handle]; exists {
		delete(rs.openDirs, handle)
		if closer, ok := d.(io.Closer); ok {
			return closer.Close()
		}
		return nil
	}
	return errNoSuchHandle
}

func (rs *server) packetWorker(ctx context.Context, pktChan chan orderedRequest) error {
	for pkt := range pktChan {
		var rpkt responsePacket
		switch pkt := pkt.requestPacket.(type) {
		case *fxpInitPkt:
			rpkt = &fxpVersionPkt{Version: ProtocolVersion}

		case *fxpOpenPkt:
			if f, err := rs.OpenFile(pkt.Path, pkt.PFlags.os(), pkt.Attr.Perms); err != nil {
				rpkt = statusFromError(pkt, err)
			} else {
				handle := rs.nextHandle()
				rs.openFilesMtx.Lock()
				rs.openFiles[handle] = f
				rs.openFilesMtx.Unlock()
				rpkt = fxpHandlePkt{pkt.ID, handle}
			}

		case *fxpClosePkt:
			err := rs.closeFile(pkt.Handle)
			if err == errNoSuchHandle {
				err = rs.closeDir(pkt.Handle)
			}
			rpkt = statusFromError(pkt, err)

		case *fxpReadPkt:
			if f, err := rs.getFile(pkt.Handle); err != nil {
				rpkt = statusFromError(pkt, err)
			} else {
				dataPkt := &fxpDataPkt{
					pkt.ID,
					make([]byte, int(pkt.Len)),
				}
				if _, err = f.ReadAt(dataPkt.Data, int64(pkt.Offset)); err != nil {
					rpkt = statusFromError(pkt, err)
				} else {
					rpkt = dataPkt
				}
			}

		case *fxpWritePkt:
			if f, err := rs.getFile(pkt.Handle); err != nil {
				rpkt = statusFromError(pkt, err)
			} else {
				_, err = f.WriteAt(pkt.Data, int64(pkt.Offset))
				rpkt = statusFromError(pkt, err)
			}

		case *fxpStatPkt:
			if info, err := rs.Stat(pkt.Path); err != nil {
				rpkt = statusFromError(pkt, err)
			} else {
				rpkt = &fxpAttrPkt{
					pkt.ID,
					fileAttrFromInfo(info),
				}
			}

		case *fxpLstatPkt:
			if info, err := rs.Lstat(pkt.Path); err != nil {
				rpkt = statusFromError(pkt, err)
			} else {
				rpkt = &fxpAttrPkt{
					pkt.ID,
					fileAttrFromInfo(info),
				}
			}

		case *fxpFstatPkt:
			if f, err := rs.getFile(pkt.Handle); err != nil {
				rpkt = statusFromError(pkt, err)
			} else {
				rpkt = &fxpAttrPkt{
					pkt.ID,
					fileAttrFromInfo(f),
				}
			}

		case *fxpSetstatPkt:
			rpkt = statusFromError(pkt, rs.Setstat(pkt.Path, pkt.Attr))

		case *fxpFsetstatPkt:
			if f, err := rs.getFile(pkt.Handle); err != nil {
				rpkt = statusFromError(pkt, err)
			} else {
				rpkt = statusFromError(pkt, f.Setstat(pkt.Attr))
			}

		case *fxpOpendirPkt:
			if d, err := rs.OpenDir(pkt.Path); err != nil {
				rpkt = statusFromError(pkt, err)
			} else {
				handle := rs.nextHandle()
				rs.openDirsMtx.Lock()
				rs.openDirs[handle] = d
				rs.openDirsMtx.Unlock()
				rpkt = &fxpHandlePkt{pkt.ID, handle}
			}

		case *fxpReaddirPkt:
			if d, err := rs.getDir(pkt.Handle); err != nil {
				rpkt = statusFromError(pkt, err)
			} else {
				files := make([]os.FileInfo, MaxReaddirItems)
				if n, err = d.ReadEntries(items); n > 0 {
					items := make([]fxpNamePktItem, n)
					for i, f := range files {
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
			rpkt = statusFromError(pkt, rs.Remove(pkt.Path))

		case *fxpMkdirPkt:
			rpkt = statusFromError(pkt, rs.Mkdir(pkt.Path, pkt.Attr))

		case *fxpRmdirPkt:
			rpkt = statusFromError(pkt, rs.Rmdir(pkt.Path))

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
			} else if abs, err := rs.RealPath(fpath); err != nil {
				rpkt = statusFromError(pkt, err)
			} else {
				rpkt = &fxpNamePkt{
					pkt.ID,
					[]fxpNamePktItem{{abs, abs, &FileAttr{}}},
				}
			}

		case *fxpRenamePkt:
			rpkt = statusFromError(pkt, rs.Rename(pkt.OldPath, pkt.NewPath))

		case *fxpReadlinkPkt:
			if fpath, err := rs.ReadLink(pkt.Path); err != nil {
				rpkt = statusFromError(pkt, err)
			} else {
				rpkt = &fxpNamePkt{
					pkt.ID,
					[]fxpNamePktItem{{fpath, fpath, &FileAttr{}}},
				}
			}

		case *fxpSymlinkPkt:
			rpkt = statusFromError(pkt, rs.Symlink(pkt.LinkPath, pkt.TargetPath))

		default:
			rpkt = statusFromError(pkt, ErrSshFxOpUnsupported)
		}

		rs.pktMgr.readyPacket(orderedResponse{rpkt, pkt.orderID()})
	}
	return nil
}

func (rs *server) cleanup() {
	// make sure all open requests are properly closed
	// (eg. possible on dropped connections, client crashes, etc.)
	for handle, req := range rs.openRequests {
		delete(rs.openRequests, handle)
		req.close()
	}
}
