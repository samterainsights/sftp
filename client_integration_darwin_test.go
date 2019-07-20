package sftp

import (
	"syscall"
	"testing"
)

func TestClientStatVFS(t *testing.T) {
	if *testServerImpl {
		t.Skipf("go server does not support FXP_EXTENDED")
	}
	sftp, cmd := testClient(t, READWRITE, NO_DELAY)
	defer cmd.Wait()
	defer sftp.Close()

	vfs, err := sftp.StatVFS("/")
	if err != nil {
		t.Fatal(err)
	}

	// get system stats
	s := syscall.Statfs_t{}
	err = syscall.Statfs("/", &s)
	if err != nil {
		t.Fatal(err)
	}

	// check some stats
	if vfs.Files != uint64(s.Files) {
		t.Fatal("fr_size does not match")
	}

	if vfs.BlocksFree != uint64(s.BlocksFree) {
		t.Fatal("f_bsize does not match")
	}

	if vfs.FilesAvail != uint64(s.FilesFree) {
		t.Fatal("f_namemax does not match")
	}
}
