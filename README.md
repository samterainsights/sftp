# Golang SFTP Client/Server

The `sftp` package implements an SFTP client interface for performing filesystem actions on a remote SSH server, as well as a server implementation for which user code can implement custom request handlers or use one of the included implementations like `sftp.MemFS()`.

[![UNIX Build Status](https://travis-ci.org/pkg/sftp.svg?branch=master)](https://travis-ci.org/pkg/sftp) [![GoDoc](https://godoc.org/github.com/pkg/sftp?status.svg)](http://godoc.org/github.com/pkg/sftp)

## Usage and Examples

See the [GoDoc](http://godoc.org/github.com/pkg/sftp) for full documentation and small examples. Larger examples can be found in the `examples/` folder.

The basic operation of the package mirrors the facilities of the [`os`](http://golang.org/pkg/os) package.

The `Walker` interface for directory traversal is heavily inspired by Keith Rarick's [`fs`](http://godoc.org/github.com/kr/fs) package.

## Contributing

We welcome pull requests, bug fixes and issue reports.

Before proposing a large change, first please discuss your change by raising an issue.

For API/code bugs, please include a small, self contained code example to reproduce the issue. For pull requests, remember test coverage.

We try to handle issues and pull requests with a **0 open** philosophy. That means we will try to address the submission as soon as possible and will work toward a resolution. If progress can no longer be made (eg. unreproducible bug) or stops (eg. unresponsive submitter), we will close the bug.

Thanks.

### Navigating the Source Code

1. The SFTP protocol spec used for reference can be found [here](https://tools.ietf.org/html/draft-ietf-secsh-filexfer-02).

1. All the low-level SFTP protocol code lies in the `proto_*.go` files. This includes values such as `SSH_FXP_INIT` and `SSH_FXF_TRUNC` (`fxpInit` and `PFlagTruncate`, respectively), as well as code for (un)marshalling the dozens of packet types.

1. The main client code is found in `client.go` (as one might expect).

1. The `Server` implementation and `RequestHandler` interface can both be found in `server.go`. All included `RequestHandler` implementations get their own distinct files which must all follow the pattern `handler_*.go`, e.g. `handler_memory_fs.go`.