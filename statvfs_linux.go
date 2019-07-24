// +build linux

package sftp

import (
	"syscall"
)

func statVFS(path string) (*StatVFS, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return nil, err
	}
	return &StatVFS{
		BlockSize:   uint64(stat.Bsize),
		FBlockSize:  uint64(stat.Frsize),
		Blocks:      stat.Blocks,
		BlocksFree:  stat.Bfree,
		BlocksAvail: stat.Bavail,
		Files:       stat.Files,
		FilesFree:   stat.Ffree,
		FilesAvail:  stat.Ffree,         // not sure how to calculate Favail
		Flag:        uint64(stat.Flags), // assuming POSIX?
		MaxNameLen:  uint64(stat.Namelen),
	}, nil
}
