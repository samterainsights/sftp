package sftp

import (
	"syscall"
)

func statvfsFromStatfst(stat *syscall.Statfs_t) (*StatVFS, error) {
	return &StatVFS{
		BlockSize:   uint64(stat.Bsize),
		FBlockSize:  uint64(stat.Bsize), // fragment size is a linux thing; use block size here
		Blocks:      stat.Blocks,
		BlocksFree:  stat.Bfree,
		BlocksAvail: stat.Bavail,
		Files:       stat.Files,
		FilesFree:   stat.Ffree,
		FilesAvail:  stat.Ffree,                                                      // not sure how to calculate FilesAvail
		FSID:        uint64(uint64(stat.Fsid.Val[1])<<32 | uint64(stat.Fsid.Val[0])), // endianness?
		Flag:        uint64(stat.Flags),                                              // assuming POSIX?
		MaxNameLen:  1024,                                                            // man 2 statfs shows: #define MAXPATHLEN      1024
	}, nil
}
