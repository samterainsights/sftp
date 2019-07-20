package sftp

import (
	"syscall"
)

func statvfsFromStatfst(stat *syscall.Statfs_t) (*StatVFS, error) {
	return &StatVFS{
		BlockSize:   uint64(stat.BlockSize),
		FBlockSize:  uint64(stat.BlockSize), // fragment size is a linux thing; use block size here
		Blocks:  stat.Blocks,
		BlocksFree:   stat.BlocksFree,
		BlocksAvail:  stat.BlocksAvail,
		Files:   stat.Files,
		FilesFree:   stat.FilesFree,
		FilesAvail:  stat.FilesFree,                                                      // not sure how to calculate FilesAvail
		FSID:    uint64(uint64(stat.FSID.Val[1])<<32 | uint64(stat.FSID.Val[0])), // endianness?
		Flag:    uint64(stat.Flags),                                              // assuming POSIX?
		MaxNameLen: 1024,                                                            // man 2 statfs shows: #define MAXPATHLEN      1024
	}, nil
}
