// +build !darwin,!linux

package sftp

func statVFS(path string) (*StatVFS, error) {
	return nil, ErrOpUnsupported
}
