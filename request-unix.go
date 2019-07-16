// +build !windows

package sftp

import (
	"errors"
	"syscall"
)

func fakeFileInfoSys() interface{} {
	return &syscall.Stat_t{Uid: 65534, Gid: 65534}
}

func testOsSys(sys interface{}) error {
	fstat := sys.(*FileStat)
	if fstat.UID != uint32(65534) {
		return errors.New("uid did not match")
	}
	if fstat.GID != uint32(65534) {
		return errors.New("gid did not match")
	}
	return nil
}
