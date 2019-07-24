package sftp

import (
	"fmt"
	"os"
)

func runLsTypeWord(f os.FileInfo) string {
	// find first character, the type char
	// b     Block special file.
	// c     Character special file.
	// d     Directory.
	// l     Symbolic link.
	// s     Socket link.
	// p     FIFO.
	// -     Regular file.
	tc := '-'
	mode := f.Mode()
	if (mode & os.ModeDir) != 0 {
		tc = 'd'
	} else if (mode & os.ModeDevice) != 0 {
		tc = 'b'
		if (mode & os.ModeCharDevice) != 0 {
			tc = 'c'
		}
	} else if (mode & os.ModeSymlink) != 0 {
		tc = 'l'
	} else if (mode & os.ModeSocket) != 0 {
		tc = 's'
	} else if (mode & os.ModeNamedPipe) != 0 {
		tc = 'p'
	}

	// owner
	orc := '-'
	if (mode & 0400) != 0 {
		orc = 'r'
	}
	owc := '-'
	if (mode & 0200) != 0 {
		owc = 'w'
	}
	oxc := '-'
	ox := (mode & 0100) != 0
	setuid := (mode & os.ModeSetuid) != 0
	if ox && setuid {
		oxc = 's'
	} else if setuid {
		oxc = 'S'
	} else if ox {
		oxc = 'x'
	}

	// group
	grc := '-'
	if (mode & 040) != 0 {
		grc = 'r'
	}
	gwc := '-'
	if (mode & 020) != 0 {
		gwc = 'w'
	}
	gxc := '-'
	gx := (mode & 010) != 0
	setgid := (mode & os.ModeSetgid) != 0
	if gx && setgid {
		gxc = 's'
	} else if setgid {
		gxc = 'S'
	} else if gx {
		gxc = 'x'
	}

	// all / others
	arc := '-'
	if (mode & 04) != 0 {
		arc = 'r'
	}
	awc := '-'
	if (mode & 02) != 0 {
		awc = 'w'
	}
	axc := '-'
	ax := (mode & 01) != 0
	sticky := (mode & os.ModeSticky) != 0
	if ax && sticky {
		axc = 't'
	} else if sticky {
		axc = 'T'
	} else if ax {
		axc = 'x'
	}

	return fmt.Sprintf("%c%c%c%c%c%c%c%c%c%c", tc, orc, owc, oxc, grc, gwc, gxc, arc, awc, axc)
}
