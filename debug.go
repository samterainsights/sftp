// +build sftp_debug

package sftp

import "fmt"

func debug(format string, args ...interface{}) {
	if format == "" || format[len(format)-1] != '\n' {
		format += "\n"
	}
	fmt.Printf(format, args...)
}
