package sftp

// This serves as an example of how to implement the request server handler as
// well as a dummy backend for testing. It implements an in-memory backend that
// works as a very simple filesystem with simple flat key-value lookup system.

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"syscall"
	"time"
)

// MemFS creates a new in-memory filesystem capable of servicing SFTP requests.
func MemFS() RequestHandler {
	return &memFS{
		memFile: newMemFile("/", true),
		files:   make(map[string]*memFile),
	}
}

// OpenFile should behave identically to os.OpenFile.
func (fs *memFS) OpenFile(string, int, os.FileMode) (FileHandle, error) {

}

// Mkdir creates a new directory. An error should be returned if the specified
// path already exists.
func (fs *memFS) Mkdir(string, *FileAttr) error {

}

// OpenDir opens a directory for scanning. An error should be returned if the
// given path is not a directory. If the returned DirReader can be cast to an
// io.Closer, its Close method will be called once the SFTP client is done
// scanning.
func (fs *memFS) OpenDir(string) (DirReader, error) {

}

// Rename renames the given path. An error should be returned if the path does
// not exist or the new path already exists.
func (fs *memFS) Rename(path, to string) error {

}

// Stat retrieves info about the given path, following symlinks.
func (fs *memFS) Stat(string) (os.FileInfo, error) {

}

// Lstat retrieves info about the given path, and does not follow symlinks,
// i.e. it can return information about symlinks themselves.
func (fs *memFS) Lstat(string) (os.FileInfo, error) {

}

// Setstat set attributes for the given path.
func (fs *memFS) Setstat(string, *FileAttr) error {

}

// Symlink creates a symlink with the given target.
func (fs *memFS) Symlink(path, target string) error {

}

// ReadLink returns the target path of the given symbolic link.
func (fs *memFS) ReadLink(string) (string, error) {
	if fs.mockErr != nil {
		return nil, fs.mockErr
	}

	fs.filesLock.Lock()
	defer fs.filesLock.Unlock()

	file, err := fs.fetch(r.Filepath)
	if err != nil {
		return nil, err
	}
	if file.symlink != "" {
		return fs.fetch(file.symlink)
	}
	return file, nil
}

// Rmdir removes the specified directory. An error should be returned if the
// given path does not exists, is not a directory, or has children.
func (fs *memFS) Rmdir(string) error {

}

// Remove removes the specified file. An error should be returned if the path
// does not exist or it is a directory.
func (fs *memFS) Remove(string) error {

}

// RealPath is responsible for producing an absolute path from a relative one.
func (fs *memFS) RealPath(string) (string, error) {

}

func (fs *memFS) Get(r *Request) (io.ReaderAt, error) {
	if fs.mockErr != nil {
		return nil, fs.mockErr
	}
	_ = r.WithContext(r.Context()) // initialize context for deadlock testing
	fs.filesLock.Lock()
	defer fs.filesLock.Unlock()
	file, err := fs.fetch(r.Filepath)
	if err != nil {
		return nil, err
	}
	if file.symlink != "" {
		file, err = fs.fetch(file.symlink)
		if err != nil {
			return nil, err
		}
	}
	return file.ReaderAt()
}

func (fs *memFS) OpenFile(r *Request) (io.WriterAt, error) {
	if fs.mockErr != nil {
		return nil, fs.mockErr
	}
	_ = r.WithContext(r.Context()) // initialize context for deadlock testing
	fs.filesLock.Lock()
	defer fs.filesLock.Unlock()
	file, err := fs.fetch(r.Filepath)
	if err == os.ErrNotExist {
		dir, err := fs.fetch(filepath.Dir(r.Filepath))
		if err != nil {
			return nil, err
		}
		if !dir.isdir {
			return nil, os.ErrInvalid
		}
		file = newMemFile(r.Filepath, false)
		fs.files[r.Filepath] = file
	}
	return file.WriterAt()
}

func (fs *memFS) Setstat(r *Request) error {
	// No-op, just return the mock error for testing (might be nil)
	return fs.mockErr
}

func (fs *memFS) Rename(r *Request) error {
	if fs.mockErr != nil {
		return fs.mockErr
	}
	_ = r.WithContext(r.Context()) // initialize context for deadlock testing
	fs.filesLock.Lock()
	defer fs.filesLock.Unlock()

	file, err := fs.fetch(r.Filepath)
	if err != nil {
		return err
	}
	if _, ok := fs.files[r.Target]; ok {
		return &os.LinkError{Op: "rename", Old: r.Filepath, New: r.Target,
			Err: fmt.Errorf("dest file exists")}
	}
	file.name = r.Target
	fs.files[r.Target] = file
	delete(fs.files, r.Filepath)

	return nil
}

func (fs *memFS) Rmdir(r *Request) error {
	if fs.mockErr != nil {
		return fs.mockErr
	}
	_ = r.WithContext(r.Context()) // initialize context for deadlock testing
	fs.filesLock.Lock()
	defer fs.filesLock.Unlock()

	_, err := fs.fetch(filepath.Dir(r.Filepath))
	if err != nil {
		return err
	}
	delete(fs.files, r.Filepath)

	return nil
}

func (fs *memFS) Mkdir(r *Request) error {
	if fs.mockErr != nil {
		return fs.mockErr
	}
	_ = r.WithContext(r.Context()) // initialize context for deadlock testing
	fs.filesLock.Lock()
	defer fs.filesLock.Unlock()

	_, err := fs.fetch(filepath.Dir(r.Filepath))
	if err != nil {
		return err
	}
	fs.files[r.Filepath] = newMemFile(r.Filepath, true)

	return nil
}

func (fs *memFS) Symlink(r *Request) error {
	if fs.mockErr != nil {
		return fs.mockErr
	}
	_ = r.WithContext(r.Context()) // initialize context for deadlock testing
	fs.filesLock.Lock()
	defer fs.filesLock.Unlock()

	_, err := fs.fetch(r.Filepath)
	if err != nil {
		return err
	}
	link := newMemFile(r.Target, false)
	link.symlink = r.Filepath
	fs.files[r.Target] = link

	return nil
}

func (fs *memFS) Remove(r *Request) error {
	if fs.mockErr != nil {
		return fs.mockErr
	}
	_ = r.WithContext(r.Context()) // initialize context for deadlock testing
	fs.filesLock.Lock()
	defer fs.filesLock.Unlock()

	_, err := fs.fetch(filepath.Dir(r.Filepath))
	if err != nil {
		return err
	}
	delete(fs.files, r.Filepath)

	return nil
}

type listerat []os.FileInfo

// Modeled after strings.Reader's ReadAt() implementation
func (f listerat) ListAt(ls []os.FileInfo, offset int64) (int, error) {
	var n int
	if offset >= int64(len(f)) {
		return 0, io.EOF
	}
	n = copy(ls, f[offset:])
	if n < len(ls) {
		return n, io.EOF
	}
	return n, nil
}

func (fs *memFS) List(r *Request) (DirReader, error) {
	if fs.mockErr != nil {
		return nil, fs.mockErr
	}
	_ = r.WithContext(r.Context()) // initialize context for deadlock testing
	fs.filesLock.Lock()
	defer fs.filesLock.Unlock()

	file, err := fs.fetch(r.Filepath)
	if err != nil {
		return nil, err
	}
	if !file.IsDir() {
		return nil, syscall.ENOTDIR
	}
	orderedNames := []string{}
	for fn := range fs.files {
		if filepath.Dir(fn) == r.Filepath {
			orderedNames = append(orderedNames, fn)
		}
	}
	sort.Strings(orderedNames)
	list := make([]os.FileInfo, len(orderedNames))
	for i, fn := range orderedNames {
		list[i] = fs.files[fn]
	}
	return listerat(list), nil
}

func (fs *memFS) Stat(r *Request) (os.FileInfo, error) {
	if fs.mockErr != nil {
		return nil, fs.mockErr
	}
	_ = r.WithContext(r.Context()) // initialize context for deadlock testing
	fs.filesLock.Lock()
	defer fs.filesLock.Unlock()

	return fs.fetch(r.Filepath)
}

// In memory file-system-y thing that the Hanlders live on
type memFS struct {
	*memFile
	files     map[string]*memFile
	filesLock sync.Mutex
	mockErr   error
}

// Set a mocked error that the next handler call will return.
// Set to nil to reset for no error.
func (fs *memFS) returnErr(err error) {
	fs.mockErr = err
}

func (fs *memFS) fetch(path string) (*memFile, error) {
	if path == "/" {
		return fs.memFile, nil
	}
	if file, ok := fs.files[path]; ok {
		return file, nil
	}
	return nil, os.ErrNotExist
}

// Implements os.FileInfo, Reader and Writer interfaces.
// These are the 3 interfaces necessary for the Handlers.
type memFile struct {
	name        string
	modtime     time.Time
	symlink     string
	isdir       bool
	content     []byte
	contentLock sync.RWMutex
}

// factory to make sure modtime is set
func newMemFile(name string, isdir bool) *memFile {
	return &memFile{
		name:    name,
		modtime: time.Now(),
		isdir:   isdir,
	}
}

// Have memFile fulfill os.FileInfo interface
func (f *memFile) Name() string { return filepath.Base(f.name) }
func (f *memFile) Size() int64  { return int64(len(f.content)) }
func (f *memFile) Mode() os.FileMode {
	ret := os.FileMode(0644)
	if f.isdir {
		ret = os.FileMode(0755) | os.ModeDir
	}
	if f.symlink != "" {
		ret = os.FileMode(0777) | os.ModeSymlink
	}
	return ret
}
func (f *memFile) ModTime() time.Time { return f.modtime }
func (f *memFile) IsDir() bool        { return f.isdir }
func (f *memFile) Sys() interface{} {
	return fakeFileInfoSys()
}

// Read/Write
func (f *memFile) ReaderAt() (io.ReaderAt, error) {
	if f.isdir {
		return nil, os.ErrInvalid
	}
	return bytes.NewReader(f.content), nil
}

func (f *memFile) WriterAt() (io.WriterAt, error) {
	if f.isdir {
		return nil, os.ErrInvalid
	}
	return f, nil
}

func (f *memFile) WriteAt(p []byte, off int64) (int, error) {
	// fmt.Println(string(p), off)
	// mimic write delays, should be optional
	time.Sleep(time.Microsecond * time.Duration(len(p)))
	f.contentLock.Lock()
	defer f.contentLock.Unlock()
	plen := len(p) + int(off)
	if plen >= len(f.content) {
		nc := make([]byte, plen)
		copy(nc, f.content)
		f.content = nc
	}
	copy(f.content[off:], p)
	return len(p), nil
}
