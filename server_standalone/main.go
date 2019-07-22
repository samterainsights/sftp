package main

// small wrapper around sftp server that allows it to be used as a separate process subsystem call by the ssh server.
// in practice this will statically link; however this allows unit testing from the sftp client.

import (
	"flag"
	"io"
	"os"

	"github.com/pkg/sftp"
)

func main() {
	var readonly bool // TODO(samterainsights): add readonly option

	flag.BoolVar(&readonly, "r", false, "read-only server (not used yet)")
	flag.Parse()

	svr, _ := sftp.NewServer(
		struct {
			io.Reader
			io.WriteCloser
		}{
			os.Stdin,
			os.Stdout,
		},
	)
	if err := svr.Serve(); err != nil {
		os.Exit(1)
	}
}
