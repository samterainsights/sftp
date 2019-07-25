package sftp

// sftp server counterpart

import (
	"os"
)

// HostFSOpts is used to configure a HostFS RequestHandler.
//
// TODO(samterainsights): Add HomeDirectory for resolving relative paths.
type HostFSOpts struct {
	AllowWrite bool // Permit requests which modify the filesystem?
}

// HostFS creates a RequestHandler wrapping the OS filesystem.
func HostFS(opts HostFSOpts) RequestHandler {
	return hostFS{opts}
}

type hostFS struct {
	HostFSOpts
}

// OpenFile should behave identically to os.OpenFile.
func (fs hostFS) OpenFile(name string, flag int, perm os.FileMode) (FileHandle, error) {
	if !fs.AllowWrite && flag&(os.O_CREATE|os.O_RDWR|os.O_WRONLY) != 0 {
		return nil, ErrPermDenied
	}
	f, err := os.OpenFile(name, flag, perm)
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if fi.IsDir() {
		f.Close()
		return nil, ErrBadMessage
	}
	return hostFile{fi, f}, nil
}

// Mkdir creates a new directory. An error should be returned if the specified
// path already exists.
func (fs hostFS) Mkdir(name string, attr *FileAttr) error {
	if !fs.AllowWrite {
		return ErrPermDenied
	}
	return os.Mkdir(name, attr.Perms)
}

// OpenDir opens a directory for scanning. An error should be returned if the
// given path is not a directory. If the returned DirReader can be cast to an
// io.Closer, its Close method will be called once the SFTP client is done
// scanning.
func (fs hostFS) OpenDir(name string) (DirReader, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if !fi.IsDir() {
		f.Close()
		return nil, ErrBadMessage
	}
	return hostDir{f}, nil
}

// Rename renames the given path. An error should be returned if the path does
// not exist or the new path already exists.
func (fs hostFS) Rename(oldpath, newpath string) error {
	if !fs.AllowWrite {
		return ErrPermDenied
	}
	return os.Rename(oldpath, newpath)
}

// Stat retrieves info about the given path, following symlinks.
func (fs hostFS) Stat(name string) (os.FileInfo, error) {
	return os.Stat(name)
}

// Lstat retrieves info about the given path, and does not follow symlinks,
// i.e. it can return information about symlinks themselves.
func (fs hostFS) Lstat(name string) (os.FileInfo, error) {
	return os.Lstat(name)
}

// Setstat set attributes for the given path.
func (fs hostFS) Setstat(name string, attr *FileAttr) (err error) {
	if !fs.AllowWrite {
		return ErrPermDenied
	}
	if attr.Flags&AttrFlagSize != 0 {
		if err = os.Truncate(name, int64(attr.Size)); err != nil {
			return
		}
	}
	if attr.Flags&AttrFlagPermissions != 0 {
		if err = os.Chmod(name, attr.Perms); err != nil {
			return
		}
	}
	if attr.Flags&AttrFlagAcModTime != 0 {
		if err = os.Chtimes(name, attr.AcTime, attr.ModTime); err != nil {
			return
		}
	}
	if attr.Flags&AttrFlagUIDGID != 0 {
		err = os.Chown(name, int(attr.UID), int(attr.GID))
	}
	return
}

// Symlink creates a symlink with the given target.
func (fs hostFS) Symlink(name, target string) error {
	if !fs.AllowWrite {
		return ErrPermDenied
	}
	return os.Symlink(target, name)
}

// ReadLink returns the target path of the given symbolic link.
func (fs hostFS) ReadLink(name string) (string, error) {
	return os.Readlink(name)
}

// Rmdir removes the specified directory. An error should be returned if the
// given path does not exists, is not a directory, or has children.
func (fs hostFS) Rmdir(name string) error {
	if !fs.AllowWrite {
		return ErrPermDenied
	}
	info, err := os.Lstat(name)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return ErrBadMessage
	}
	return os.Remove(name)
}

// Remove removes the specified file. An error should be returned if the path
// does not exist or it is a directory.
func (fs hostFS) Remove(name string) error {
	if !fs.AllowWrite {
		return ErrPermDenied
	}
	info, err := os.Lstat(name)
	if err != nil {
		return err
	}
	if info.IsDir() {
		return ErrBadMessage
	}
	return os.Remove(name)
}

// RealPath is responsible for producing an absolute path from a relative one.
func (fs hostFS) RealPath(name string) (string, error) {
	return "", ErrOpUnsupported // TODO(samterainsights)
}

type hostFile struct {
	os.FileInfo
	raw *os.File
}

func (f hostFile) ReadAt(dst []byte, offset int64) (int, error) {
	return f.raw.ReadAt(dst, offset)
}

func (f hostFile) WriteAt(data []byte, offset int64) (int, error) {
	return f.raw.WriteAt(data, offset)
}

func (f hostFile) Close() error {
	return f.raw.Close()
}

func (f hostFile) Setstat(attr *FileAttr) (err error) {
	if attr.Flags&AttrFlagSize != 0 {
		if err = f.raw.Truncate(int64(attr.Size)); err != nil {
			return
		}
	}
	if attr.Flags&AttrFlagPermissions != 0 {
		if err = f.raw.Chmod(attr.Perms); err != nil {
			return
		}
	}
	if attr.Flags&AttrFlagAcModTime != 0 {
		if err = os.Chtimes(f.raw.Name(), attr.AcTime, attr.ModTime); err != nil {
			return
		}
	}
	if attr.Flags&AttrFlagUIDGID != 0 {
		if err = f.raw.Chown(int(attr.UID), int(attr.GID)); err != nil {
			return
		}
	}
	return
}

type hostDir struct {
	*os.File
}

func (d hostDir) ReadEntries(dst []os.FileInfo) (copied int, err error) {
	var entries []os.FileInfo
	for copied < len(dst) && err == nil {
		entries, err = d.Readdir(len(dst) - copied)
		copy(dst[copied:], entries)
	}
	return
}
