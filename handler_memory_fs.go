package sftp

// This serves as an example of how to implement the request server handler as
// well as a dummy backend for testing. It implements an in-memory backend that
// works as a very simple filesystem with simple flat key-value lookup system.

import (
	"io"
	"os"
	"path/filepath"
	"sync"
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
func (fs *memFS) OpenFile(name string, flag int, perm os.FileMode) (FileHandle, error) {
	return nil, nil // TODO(samterainsights)
}

// Mkdir creates a new directory. An error should be returned if the specified
// path already exists.
func (fs *memFS) Mkdir(name string, attr *FileAttr) error {
	return nil // TODO(samterainsights)
}

// OpenDir opens a directory for scanning. An error should be returned if the
// given path is not a directory. If the returned DirReader can be cast to an
// io.Closer, its Close method will be called once the SFTP client is done
// scanning.
func (fs *memFS) OpenDir(name string) (DirReader, error) {
	return nil, nil // TODO(samterainsights)
}

// Rename renames the given path. An error should be returned if the path does
// not exist or the new path already exists.
func (fs *memFS) Rename(oldpath, newpath string) error {
	return nil // TODO(samterainsights)
}

// Stat retrieves info about the given path, following symlinks.
func (fs *memFS) Stat(name string) (os.FileInfo, error) {
	return nil, nil // TODO(samterainsights)
}

// Lstat retrieves info about the given path, and does not follow symlinks,
// i.e. it can return information about symlinks themselves.
func (fs *memFS) Lstat(name string) (os.FileInfo, error) {
	return nil, nil // TODO(samterainsights)
}

// Setstat set attributes for the given path.
func (fs *memFS) Setstat(name string, attr *FileAttr) error {
	return nil // TODO(samterainsights)
}

// Symlink creates a symlink with the given target.
func (fs *memFS) Symlink(name, target string) error {
	return nil // TODO(samterainsights)
}

// ReadLink returns the target path of the given symbolic link.
func (fs *memFS) ReadLink(name string) (string, error) {
	return "", nil // TODO(samterainsights)
}

// Rmdir removes the specified directory. An error should be returned if the
// given path does not exists, is not a directory, or has children.
func (fs *memFS) Rmdir(name string) error {
	return nil // TODO(samterainsights)
}

// Remove removes the specified file. An error should be returned if the path
// does not exist or it is a directory.
func (fs *memFS) Remove(name string) error {
	return nil // TODO(samterainsights)
}

// RealPath is responsible for producing an absolute path from a relative one.
func (fs *memFS) RealPath(name string) (string, error) {
	return "", nil // TODO(samterainsights)
}

// In memory file-system-y thing that the Hanlders live on
type memFS struct {
	*memFile
	files     map[string]*memFile
	filesLock sync.Mutex
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
	return nil
}

func (f *memFile) ReaderAt() (io.ReaderAt, error) {
	return f, nil
}

func (f *memFile) ReadAt(p []byte, off int64) (int, error) {
	f.contentLock.RLock()
	defer f.contentLock.RUnlock()
	return copy(p, f.content[off:]), nil
}

func (f *memFile) WriterAt() (io.WriterAt, error) {
	return f, nil
}

func (f *memFile) WriteAt(p []byte, off int64) (int, error) {
	f.contentLock.Lock()
	defer f.contentLock.Unlock()

	minLen := len(p) + int(off)
	if minLen >= len(f.content) {
		nc := make([]byte, minLen)
		copy(nc, f.content)
		f.content = nc
	}
	copy(f.content[off:], p)

	return len(p), nil
}
