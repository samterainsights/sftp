// +build linux

package sftp

import (
	"syscall"
)

func statvfsFromStatfst(stat *syscall.Statfs_t) (*StatVFS, error) {
	return &StatVFS{
		BlockSize:   uint64(stat.BlockSize),
		FBlockSize:  uint64(stat.FBlockSize),
		Blocks:  stat.Blocks,
		BlocksFree:   stat.BlocksFree,
		BlocksAvail:  stat.BlocksAvail,
		Files:   stat.Files,
		FilesFree:   stat.FilesFree,
		FilesAvail:  stat.FilesFree,         // not sure how to calculate FilesAvail
		Flag:    uint64(stat.Flags), // assuming POSIX?
		MaxNameLen: uint64(stat.Namelen),
	}, nil
}
