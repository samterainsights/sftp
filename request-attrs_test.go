package sftp

import (
	"os"

	"github.com/stretchr/testify/assert"

	"testing"
)

func TestRequestPflags(t *testing.T) {
	pflags := newFileOpenFlags(ssh_FXF_READ | ssh_FXF_WRITE | ssh_FXF_APPEND)
	assert.True(t, pflags.Read)
	assert.True(t, pflags.Write)
	assert.True(t, pflags.Append)
	assert.False(t, pflags.Creat)
	assert.False(t, pflags.Trunc)
	assert.False(t, pflags.Excl)
}

func TestRequestAflags(t *testing.T) {
	aflags := newFileAttrFlags(
		ssh_FILEXFER_ATTR_SIZE | ssh_FILEXFER_ATTR_UIDGID)
	assert.True(t, aflags.Size)
	assert.True(t, aflags.UIDGID)
	assert.False(t, aflags.Acmodtime)
	assert.False(t, aflags.Permissions)
}

func TestRequestAttributes(t *testing.T) {
	// UID/GID
	fa := FileStat{UID: 1, GID: 2}
	fl := uint32(ssh_FILEXFER_ATTR_UIDGID)
	at := []byte{}
	at = marshalUint32(at, 1)
	at = marshalUint32(at, 2)
	testFS, _ := getFileStat(fl, at)
	assert.Equal(t, fa, *testFS)
	// Size and Mode
	fa = FileStat{Mode: 700, Size: 99}
	fl = uint32(ssh_FILEXFER_ATTR_SIZE | ssh_FILEXFER_ATTR_PERMISSIONS)
	at = []byte{}
	at = marshalUint64(at, 99)
	at = marshalUint32(at, 700)
	testFS, _ = getFileStat(fl, at)
	assert.Equal(t, fa, *testFS)
	// FileMode
	assert.True(t, testFS.FileMode().IsRegular())
	assert.False(t, testFS.FileMode().IsDir())
	assert.Equal(t, testFS.FileMode().Perm(), os.FileMode(700).Perm())
}
