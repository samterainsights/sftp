# Golang SFTP Server

[![GoDoc](https://godoc.org/github.com/tera-insights/sftp?status.svg)](https://godoc.org/github.com/tera-insights/sftp)

The `sftp` package implements the SFTP server protocol. To serve SFTP, you need only an `io.ReadWriter` for the packet transport (typically this will be an SSH channel), and a `RequestHandler` implementation.

This package currently provides two `RequestHandler` implementations for your convenience: an in-memory filesystem (`MemFS`) and a wrapper around the OS filesystem (`HostFS`). Both implementations are excellent references for writing your own driver.

See the [GoDoc](http://godoc.org/github.com/tera-insights/sftp) for full documentation and small examples. Larger examples can be found in the `examples/` folder.

## Contributing

We welcome pull requests, bug fixes and issue reports.

Before proposing a large change, first please discuss your change by raising an issue.

For API/code bugs, please include a small, self contained code example to reproduce the issue. For pull requests, remember test coverage.

We try to handle issues and pull requests with a **0 open** philosophy. That means we will try to address the submission as soon as possible and will work toward a resolution. If progress can no longer be made (eg. unreproducible bug) or stops (eg. unresponsive submitter), we will close the bug.

Thanks.

### Navigating the Source Code

The SFTP protocol spec used for reference can be found [here](https://tools.ietf.org/pdf/draft-ietf-secsh-filexfer-02). Please also review the [OpenSSH extensions and **changes**](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL#L344), as they influenced most of the SFTP ecosystem.

- `packets.go`

    All (un)marshaling code for *standard* SFTP packets. Please respect the `fxp<type>Pkt` naming convention. **Do not** propose using the `reflect` or `encoding/binary` packages for marshaling unless you can prove that they are not vastly slower than manually-written marshaling code.

    > **Note:** Packets do not technically adhere to the `encoding.BinaryMarshaler/Unmarshaler` interfaces. This is done for significant performance gains, and packet types are not exposed by the package so it should be a non-issue. Namely, `fxpWritePkt` retains a subslice of the data passed to `Unmarshal`, and packets cannot directly unmarshal themselves from their marshaled forms. Both of these gotchas should be pretty easy to keep in check and allow for minimal copying and memory usage.

- `packets_extended.go`

    All (un)marshaling code for *extended* packets. Please respect the `fxpExt<type>Pkt` naming convention and read the `packets.go` note above.

- `sftp.go`

    Contains all the SFTP protocol constants, like packet types and file open flags. Please respect the `fxp<type>` naming convention, e.g. `SSH_FXP_INIT` becomes `fxpInit` and `SSH_FXP_READDIR` becomes `fxpReaddir`.

- `server.go`

    Contains the `Serve(io.ReadWriter, RequestHandler)` implementation and also the `RequestHandler` interface.

- `handler_*.go`

    Each `RequestHandler` implementation gets its own file, prefixed with `handler_`.

- **TODO(samterainsights):** rest of the files cleanup/documentation...