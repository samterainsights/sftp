// +build !cgo,!plan9 windows android

package sftp

import (
	"os"
)

func fileAttrFromInfoOS(fi os.FileInfo, attr *FileAttr) {
	// todo
}
