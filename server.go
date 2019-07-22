package sftp

import (
	"context"
	"io"
	"os"
	"path"
	"strconv"
	"sync"
	"syscall"

	"github.com/pkg/errors"
)

var maxTxPacket uint32 = 1 << 15

// A FileHandle is an TODO(samterainsights)
type FileHandle interface {
	os.FileInfo
	io.ReaderAt
	io.WriterAt
	io.Closer

	Setstat(*FileAttr) error
}

// ListerAt does for file lists what io.ReaderAt does for files.
// ListAt should return the number of entries copied and an io.EOF
// error if at end of list. This is testable by comparing how many you
// copied to how many could be copied (eg. n < len(ls) below).
// The copy() builtin is best for the copying.
// Note in cases of an error, the error text will be sent to the client.
type ListerAt interface {
	ListAt([]os.FileInfo, int64) (int, error)
}

// RequestHandler is responsible for handling the various kinds of SFTP requests.
// Two implementations are provided by this library: an in-memory filesystem and
// a wrapper around the OS filesystem.
type RequestHandler interface {
	// OpenFile should behave identically to os.OpenFile. If the returned FileHandle
	// has a Handle() method which returns a string, that handle will be used
	// internally for the SFTP protocol. Otherwise, the filepath will be used.
	OpenFile(string, int, os.FileMode) (FileHandle, error)

	// Mkdir creates a new directory. An error should be returned if the specified
	// path already exists.
	Mkdir(string, *FileAttr) error

	// OpenDir opens a directory for scanning. An error should be returned if the
	// given path is not a directory. If the returned ListerAt can be cast to an
	// io.Closer, its Close method will be called once the SFTP client is done
	// scanning.
	OpenDir(string) (ListerAt, error)

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
}

// server abstracts the sftp protocol with an http request-like protocol
type server struct {
	*conn
	RequestHandler

	pktMgr          *packetManager
	openRequests    map[string]*Request
	openRequestLock sync.RWMutex
	handleCount     int
}

type noopCloseRWC struct {
	io.ReadWriter
}

func (rwc noopCloseRWC) Close() error { return nil }

// Serve the SFTP protocol over a connection. Generally you will want to serve it on top
// of an SSH "session" channel, however it could also be served over TLS, etc. Note that
// SFTP has no security provisions so it should always be layered on top of a secure
// connection.
func Serve(transport io.ReadWriter, handler RequestHandler) error {
	conn := &conn{
		Reader:      transport,
		WriteCloser: noopCloseRWC{transport},
	}
	rs := &server{
		conn:           conn,
		RequestHandler: handler,
		pktMgr:         newPktMgr(conn),
		openRequests:   make(map[string]*Request),
	}

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

	var err error
	var pktType uint8
	var pktBytes []byte
	for {
		pktType, pktBytes, err = rs.recvPacket()
		if err != nil {
			break
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

	close(pktChan) // shuts down sftpServerWorkers
	wg.Wait()      // wait for all workers to exit

	// make sure all open requests are properly closed
	// (eg. possible on dropped connections, client crashes, etc.)
	for handle, req := range rs.openRequests {
		delete(rs.openRequests, handle)
		req.close()
	}

	return err
}

// New Open packet/Request
func (rs *server) nextRequest(r *Request) string {
	rs.openRequestLock.Lock()
	defer rs.openRequestLock.Unlock()
	rs.handleCount++
	handle := strconv.Itoa(rs.handleCount)
	r.handle = handle
	rs.openRequests[handle] = r
	return handle
}

// Returns Request from openRequests, bool is false if it is missing.
//
// The Requests in openRequests work essentially as open file descriptors that
// you can do different things with. What you are doing with it are denoted by
// the first packet of that type (read/write/etc).
func (rs *server) getRequest(handle string) (*Request, bool) {
	rs.openRequestLock.RLock()
	defer rs.openRequestLock.RUnlock()
	r, ok := rs.openRequests[handle]
	return r, ok
}

// Close the Request and clear from openRequests map
func (rs *server) closeRequest(handle string) error {
	rs.openRequestLock.Lock()
	defer rs.openRequestLock.Unlock()
	if r, ok := rs.openRequests[handle]; ok {
		delete(rs.openRequests, handle)
		return r.close()
	}
	return syscall.EBADF
}

// Close the read/write/closer to trigger exiting the main server loop
func (rs *server) Close() error { return rs.conn.Close() }

func (rs *server) packetWorker(
	ctx context.Context, pktChan chan orderedRequest,
) error {
	for pkt := range pktChan {
		var rpkt responsePacket
		switch pkt := pkt.requestPacket.(type) {
		case *fxpInitPkt:
			rpkt = &fxpVersionPkt{Version: sftpProtocolVersion}
		case *fxpClosePkt:
			handle := pkt.getHandle()
			rpkt = statusFromError(pkt, rs.closeRequest(handle))
		case *fxpRealpathPkt:
			path := path.Clean(pkt.Path)
			rpkt = &fxpNamePkt{
				ID: pkt.id(),
				Items: []fxpNamePktItem{{
					Name:     path,
					LongName: path,
					Attr:     &FileAttr{},
				}},
			}
		case *fxpOpendirPkt:
			request := requestFromPacket(ctx, pkt)
			rs.nextRequest(request)
			rpkt = request.opendir(rs.Handlers, pkt)
		case *fxpOpenPkt:
			request := requestFromPacket(ctx, pkt)
			rs.nextRequest(request)
			rpkt = request.open(rs.Handlers, pkt)
		case *fxpFstatPkt:
			handle := pkt.getHandle()
			request, ok := rs.getRequest(handle)
			if !ok {
				rpkt = statusFromError(pkt, syscall.EBADF)
			} else {
				request = NewRequest("Stat", request.Filepath)
				rpkt = request.call(rs.Handlers, pkt)
			}
		case hasHandle:
			handle := pkt.getHandle()
			request, ok := rs.getRequest(handle)
			if !ok {
				rpkt = statusFromError(pkt, syscall.EBADF)
			} else {
				rpkt = request.call(rs.Handlers, pkt)
			}
		case hasPath:
			request := requestFromPacket(ctx, pkt)
			rpkt = request.call(rs.Handlers, pkt)
			request.close()
		default:
			return errors.Errorf("unexpected packet type %T", pkt)
		}

		rs.pktMgr.readyPacket(orderedResponse{rpkt, pkt.orderID()})
	}
	return nil
}
