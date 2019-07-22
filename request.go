package sftp

import (
	"context"
	"io"
	"os"
	"path"
	"path/filepath"
	"sync"
	"syscall"

	"github.com/pkg/errors"
)

// MaxFilelist is the max number of files to return in a readdir batch.
var MaxFilelist int64 = 100

// Request contains the data and state for the incoming service request.
type Request struct {
	// Get, Put, Setstat, Stat, Rename, Remove
	// Rmdir, Mkdir, List, Readlink, Symlink
	Method   string
	Filepath string
	PFlags   pflag
	Attrs    *FileAttr
	Target   string // for renames and sym-links
	handle   string
	// reader/writer/readdir from handlers
	state state
	// context lasts duration of request
	ctx       context.Context
	cancelCtx context.CancelFunc
}

type state struct {
	*sync.RWMutex
	writerAt io.WriterAt
	readerAt io.ReaderAt
	listerAt ListerAt
	lsoffset int64
}

// New Request initialized based on packet data
func requestFromPacket(ctx context.Context, pkt hasPath) *Request {
	method := requestMethod(pkt)
	request := NewRequest(method, pkt.getPath())
	request.ctx, request.cancelCtx = context.WithCancel(ctx)

	switch p := pkt.(type) {
	case *fxpOpenPkt:
		request.PFlags = p.PFlags
	case *fxpSetstatPkt:
		request.Attrs = p.Attr
	case *fxpRenamePkt:
		request.Target = path.Clean(p.NewPath)
	case *fxpSymlinkPkt:
		request.Target = path.Clean(p.LinkPath)
	}
	return request
}

// NewRequest creates a new Request object.
func NewRequest(method, path string) *Request {
	return &Request{
		Method:   method,
		Filepath: path.Clean(path),
		state:    state{RWMutex: new(sync.RWMutex)},
	}
}

// shallow copy of existing request
func (r *Request) copy() *Request {
	r.state.Lock()
	defer r.state.Unlock()
	r2 := new(Request)
	*r2 = *r
	return r2
}

// Context returns the request's context. To change the context,
// use WithContext.
//
// The returned context is always non-nil; it defaults to the
// background context.
//
// For incoming server requests, the context is canceled when the
// request is complete or the client's connection closes.
func (r *Request) Context() context.Context {
	if r.ctx != nil {
		return r.ctx
	}
	return context.Background()
}

// WithContext returns a copy of r with its context changed to ctx.
// The provided ctx must be non-nil.
func (r *Request) WithContext(ctx context.Context) *Request {
	if ctx == nil {
		panic("nil context")
	}
	r2 := r.copy()
	r2.ctx = ctx
	r2.cancelCtx = nil
	return r2
}

// Returns current offset for file list
func (r *Request) lsNext() int64 {
	r.state.RLock()
	defer r.state.RUnlock()
	return r.state.lsoffset
}

// Increases next offset
func (r *Request) lsInc(offset int64) {
	r.state.Lock()
	defer r.state.Unlock()
	r.state.lsoffset = r.state.lsoffset + offset
}

// manage file read/write state
func (r *Request) setListerState(la ListerAt) {
	r.state.Lock()
	defer r.state.Unlock()
	r.state.listerAt = la
}

func (r *Request) getLister() ListerAt {
	r.state.RLock()
	defer r.state.RUnlock()
	return r.state.listerAt
}

// Close reader/writer if possible
func (r *Request) close() error {
	defer func() {
		if r.cancelCtx != nil {
			r.cancelCtx()
		}
	}()
	r.state.RLock()
	rd := r.state.readerAt
	r.state.RUnlock()
	if c, ok := rd.(io.Closer); ok {
		return c.Close()
	}
	r.state.RLock()
	wt := r.state.writerAt
	r.state.RUnlock()
	if c, ok := wt.(io.Closer); ok {
		return c.Close()
	}
	return nil
}

// called from worker to handle packet/request
func (r *Request) call(h RequestHandler, pkt requestPacket) responsePacket {
	switch r.Method {
	case "Get":
		r.state.RLock()
		reader := r.state.readerAt
		r.state.RUnlock()
		if reader == nil {
			return statusFromError(pkt, errors.New("unexpected read packet"))
		}

		_, offset, length := packetData(pkt)
		data := make([]byte, clamp(length, maxTxPacket))
		n, err := reader.ReadAt(data, offset)
		// only return EOF erro if no data left to read
		if err != nil && (err != io.EOF || n == 0) {
			return statusFromError(pkt, err)
		}
		return &fxpDataPkt{
			ID:   pkt.id(),
			Data: data[:n],
		}

	case "Put":
		r.state.RLock()
		writer := r.state.writerAt
		r.state.RUnlock()
		if writer == nil {
			return statusFromError(pkt, errors.New("unexpected write packet"))
		}

		data, offset, _ := packetData(pkt)
		_, err := writer.WriteAt(data, offset)
		return statusFromError(pkt, err)

	case "Setstat":
		if p, ok := pkt.(*fxpFsetstatPkt); ok {
			r.Attrs = p.Attr
		}
		return statusFromError(pkt, h.Setstat(r))

	case "Rename":
		return statusFromError(pkt, h.Rename(r))

	case "Rmdir":
		return statusFromError(pkt, h.Rmdir(r))

	case "Mkdir":
		return statusFromError(pkt, h.Mkdir(r))

	case "Symlink":
		return statusFromError(pkt, h.Symlink(r))

	case "Remove":
		return statusFromError(pkt, h.Remove(r))

	case "List":
		var err error
		lister := r.getLister()
		if lister == nil {
			return statusFromError(pkt, errors.New("unexpected dir packet"))
		}

		offset := r.lsNext()
		finfo := make([]os.FileInfo, MaxFilelist)
		n, err := lister.ListAt(finfo, offset)
		r.lsInc(int64(n))
		// ignore EOF as we only return it when there are no results
		finfo = finfo[:n] // avoid need for nil tests below

		if err != nil && err != io.EOF {
			return statusFromError(pkt, err)
		}
		if err == io.EOF && n == 0 {
			return statusFromError(pkt, io.EOF)
		}
		dirname := filepath.ToSlash(path.Base(r.Filepath))
		ret := &fxpNamePkt{pkt.id(), make([]fxpNamePktItem, 0, len(finfo))}

		for _, fi := range finfo {
			ret.Items = append(ret.Items, fxpNamePktItem{
				Name:     fi.Name(),
				LongName: runLs(dirname, fi),
				Attr:     fileAttrFromInfo(fi),
			})
		}
		return ret

	case "Stat":
		info, err := h.Stat(r)
		if err != nil {
			return statusFromError(pkt, err)
		}
		return &fxpAttrPkt{pkt.id(), fileAttrFromInfo(info)}

	case "Readlink":
		info, err := h.ReadLink(r)
		if err != nil {
			return statusFromError(pkt, err)
		}
		filename := info.Name()
		return &fxpNamePkt{
			ID: pkt.id(),
			Items: []fxpNamePktItem{{
				Name:     filename,
				LongName: filename,
				Attr:     &FileAttr{},
			}},
		}

	default:
		return statusFromError(pkt, errors.Errorf("unexpected method: %s", r.Method))
	}
}

// Additional initialization for Open packets
func (r *Request) open(h RequestHandler, pkt requestPacket) responsePacket {
	var err error
	if r.PFlags&(PFlagWrite|PFlagAppend|PFlagCreate|PFlagTruncate) != 0 {
		r.Method = "Put"
		r.state.writerAt, err = h.OpenFile(r)
	} else if r.PFlags&PFlagRead != 0 {
		r.Method = "Get"
		r.state.readerAt, err = h.Get(r)
	} else {
		err = errors.New("bad file flags")
	}
	if err != nil {
		return statusFromError(pkt, err)
	}
	return &fxpHandlePkt{ID: pkt.id(), Handle: r.handle}
}

func (r *Request) opendir(h RequestHandler, pkt requestPacket) responsePacket {
	var err error
	r.Method = "List"
	r.state.listerAt, err = h.List(r)
	if err != nil {
		switch err.(type) {
		case syscall.Errno:
			err = &os.PathError{Path: r.Filepath, Err: err}
		}
		return statusFromError(pkt, err)
	}
	return &fxpHandlePkt{ID: pkt.id(), Handle: r.handle}
}

// file data for additional read/write packets
func packetData(p requestPacket) (data []byte, offset int64, length uint32) {
	switch p := p.(type) {
	case *fxpReadPkt:
		length = p.Len
		offset = int64(p.Offset)
	case *fxpWritePkt:
		data = p.Data
		length = uint32(len(p.Data))
		offset = int64(p.Offset)
	}
	return
}

// init attributes of request object from packet data
func requestMethod(p requestPacket) (method string) {
	switch p.(type) {
	case *fxpReadPkt, *fxpWritePkt, *fxpOpenPkt:
		// set in open() above
	case *fxpOpendirPkt, *fxpReaddirPkt:
		// set in opendir() above
	case *fxpSetstatPkt, *fxpFsetstatPkt:
		method = "Setstat"
	case *fxpRenamePkt:
		method = "Rename"
	case *fxpSymlinkPkt:
		method = "Symlink"
	case *fxpRemovePkt:
		method = "Remove"
	case *fxpStatPkt, *fxpLstatPkt, *fxpFstatPkt:
		method = "Stat"
	case *fxpRmdirPkt:
		method = "Rmdir"
	case *fxpReadlinkPkt:
		method = "Readlink"
	case *fxpMkdirPkt:
		method = "Mkdir"
	}
	return method
}
