package sftp

import (
	"bytes"
	"encoding"
	"os"
	"testing"
)

var appendU32Tests = []struct {
	v    uint32
	want []byte
}{
	{1, []byte{0, 0, 0, 1}},
	{256, []byte{0, 0, 1, 0}},
	{^uint32(0), []byte{255, 255, 255, 255}},
}

func TestMarshalUint32(t *testing.T) {
	for _, tt := range appendU32Tests {
		got := appendU32(nil, tt.v)
		if !bytes.Equal(tt.want, got) {
			t.Errorf("appendU32(%d): want %v, got %v", tt.v, tt.want, got)
		}
	}
}

var appendU64Tests = []struct {
	v    uint64
	want []byte
}{
	{1, []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1}},
	{256, []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0}},
	{^uint64(0), []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}},
	{1 << 32, []byte{0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0}},
}

func TestMarshalUint64(t *testing.T) {
	for _, tt := range appendU64Tests {
		got := appendU64(nil, tt.v)
		if !bytes.Equal(tt.want, got) {
			t.Errorf("marshalUint64(%d): want %#v, got %#v", tt.v, tt.want, got)
		}
	}
}

var appendStrTests = []struct {
	v    string
	want []byte
}{
	{"", []byte{0, 0, 0, 0}},
	{"/foo", []byte{0x0, 0x0, 0x0, 0x4, 0x2f, 0x66, 0x6f, 0x6f}},
}

func TestMarshalString(t *testing.T) {
	for _, tt := range appendStrTests {
		got := appendStr(nil, tt.v)
		if !bytes.Equal(tt.want, got) {
			t.Errorf("marshalString(%q): want %#v, got %#v", tt.v, tt.want, got)
		}
	}
}

var marshalTests = []struct {
	v    interface{}
	want []byte
}{
	{uint8(1), []byte{1}},
	{byte(1), []byte{1}},
	{uint32(1), []byte{0, 0, 0, 1}},
	{uint64(1), []byte{0, 0, 0, 0, 0, 0, 0, 1}},
	{"foo", []byte{0x0, 0x0, 0x0, 0x3, 0x66, 0x6f, 0x6f}},
	{[]uint32{1, 2, 3, 4}, []byte{0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x2, 0x0, 0x0, 0x0, 0x3, 0x0, 0x0, 0x0, 0x4}},
}

func TestMarshal(t *testing.T) {
	for _, tt := range marshalTests {
		got := marshal(nil, tt.v)
		if !bytes.Equal(tt.want, got) {
			t.Errorf("marshal(%v): want %#v, got %#v", tt.v, tt.want, got)
		}
	}
}

var takeU32Tests = []struct {
	b    []byte
	want uint32
	rest []byte
}{
	{[]byte{0, 0, 0, 0}, 0, nil},
	{[]byte{0, 0, 1, 0}, 256, nil},
	{[]byte{255, 0, 0, 255}, 4278190335, nil},
}

func TestUnappendU32(t *testing.T) {
	for _, tt := range takeU32Tests {
		got, rest := takeU32(tt.b)
		if got != tt.want || !bytes.Equal(rest, tt.rest) {
			t.Errorf("takeU32(%v): want %v, %#v, got %v, %#v", tt.b, tt.want, tt.rest, got, rest)
		}
	}
}

var takeU64Tests = []struct {
	b    []byte
	want uint64
	rest []byte
}{
	{[]byte{0, 0, 0, 0, 0, 0, 0, 0}, 0, nil},
	{[]byte{0, 0, 0, 0, 0, 0, 1, 0}, 256, nil},
	{[]byte{255, 0, 0, 0, 0, 0, 0, 255}, 18374686479671623935, nil},
}

func TestUnmarshalUint64(t *testing.T) {
	for _, tt := range takeU64Tests {
		got, rest := takeU64(tt.b)
		if got != tt.want || !bytes.Equal(rest, tt.rest) {
			t.Errorf("takeU64(%v): want %v, %#v, got %v, %#v", tt.b, tt.want, tt.rest, got, rest)
		}
	}
}

var takeStrTests = []struct {
	b    []byte
	want string
	rest []byte
}{
	{marshalString(nil, ""), "", nil},
	{marshalString(nil, "blah"), "blah", nil},
}

func TestUnmarshalString(t *testing.T) {
	for _, tt := range takeStrTests {
		got, rest := takeStr(tt.b)
		if got != tt.want || !bytes.Equal(rest, tt.rest) {
			t.Errorf("takeU64(%v): want %q, %#v, got %q, %#v", tt.b, tt.want, tt.rest, got, rest)
		}
	}
}

var sendPacketTests = []struct {
	p    encoding.BinaryMarshaler
	want []byte
}{
	{fxpInitPkt{
		Version: 3,
		Extensions: []extensionPair{
			{"posix-rename@openssh.com", "1"},
		},
	}, []byte{0x0, 0x0, 0x0, 0x26, 0x1, 0x0, 0x0, 0x0, 0x3, 0x0, 0x0, 0x0, 0x18, 0x70, 0x6f, 0x73, 0x69, 0x78, 0x2d, 0x72, 0x65, 0x6e, 0x61, 0x6d, 0x65, 0x40, 0x6f, 0x70, 0x65, 0x6e, 0x73, 0x73, 0x68, 0x2e, 0x63, 0x6f, 0x6d, 0x0, 0x0, 0x0, 0x1, 0x31}},

	{fxpOpenPkt{
		ID:     1,
		Path:   "/foo",
		Pflags: flags(os.O_RDONLY),
	}, []byte{0x0, 0x0, 0x0, 0x15, 0x3, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x4, 0x2f, 0x66, 0x6f, 0x6f, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0}},

	{fxpWritePkt{
		ID:     124,
		Handle: "foo",
		Offset: 13,
		Length: uint32(len([]byte("bar"))),
		Data:   []byte("bar"),
	}, []byte{0x0, 0x0, 0x0, 0x1b, 0x6, 0x0, 0x0, 0x0, 0x7c, 0x0, 0x0, 0x0, 0x3, 0x66, 0x6f, 0x6f, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xd, 0x0, 0x0, 0x0, 0x3, 0x62, 0x61, 0x72}},

	{fxpSetstatPkt{
		ID:    31,
		Path:  "/bar",
		Flags: flags(os.O_WRONLY),
		Attrs: struct {
			UID uint32
			GID uint32
		}{1000, 100},
	}, []byte{0x0, 0x0, 0x0, 0x19, 0x9, 0x0, 0x0, 0x0, 0x1f, 0x0, 0x0, 0x0, 0x4, 0x2f, 0x62, 0x61, 0x72, 0x0, 0x0, 0x0, 0x2, 0x0, 0x0, 0x3, 0xe8, 0x0, 0x0, 0x0, 0x64}},
}

func TestSendPacket(t *testing.T) {
	for _, tt := range sendPacketTests {
		var w bytes.Buffer
		sendPacket(&w, tt.p)
		if got := w.Bytes(); !bytes.Equal(tt.want, got) {
			t.Errorf("sendPacket(%v): want %#v, got %#v", tt.p, tt.want, got)
		}
	}
}

func sp(p encoding.BinaryMarshaler) []byte {
	var w bytes.Buffer
	sendPacket(&w, p)
	return w.Bytes()
}

var readPacketTests = []struct {
	b    []byte
	want uint8
	rest []byte
}{
	{sp(fxpInitPkt{
		Version: 3,
		Extensions: []extensionPair{
			{"posix-rename@openssh.com", "1"},
		},
	}), fxpInit, []byte{0x0, 0x0, 0x0, 0x3, 0x0, 0x0, 0x0, 0x18, 0x70, 0x6f, 0x73, 0x69, 0x78, 0x2d, 0x72, 0x65, 0x6e, 0x61, 0x6d, 0x65, 0x40, 0x6f, 0x70, 0x65, 0x6e, 0x73, 0x73, 0x68, 0x2e, 0x63, 0x6f, 0x6d, 0x0, 0x0, 0x0, 0x1, 0x31}},
}

func TestRecvPacket(t *testing.T) {
	for _, tt := range readPacketTests {
		r := bytes.NewReader(tt.b)
		got, rest, _ := readPacket(r)
		if got != tt.want || !bytes.Equal(rest, tt.rest) {
			t.Errorf("readPacket(%#v): want %v, %#v, got %v, %#v", tt.b, tt.want, tt.rest, got, rest)
		}
	}
}

func TestSSHFxpOpenPacketreadonly(t *testing.T) {
	var tests = []struct {
		pflags uint32
		ok     bool
	}{
		{
			pflags: PFlagRead,
			ok:     true,
		},
		{
			pflags: PFlagWrite,
			ok:     false,
		},
		{
			pflags: PFlagRead | PFlagWrite,
			ok:     false,
		},
	}

	for _, tt := range tests {
		p := &fxpOpenPkt{
			Pflags: tt.pflags,
		}

		if want, got := tt.ok, p.readonly(); want != got {
			t.Errorf("unexpected value for p.readonly(): want: %v, got: %v",
				want, got)
		}
	}
}

func TestSSHFxpOpenPackethasPflags(t *testing.T) {
	var tests = []struct {
		desc      string
		haveFlags uint32
		testFlags []uint32
		ok        bool
	}{
		{
			desc:      "have read, test against write",
			haveFlags: PFlagRead,
			testFlags: []uint32{PFlagWrite},
			ok:        false,
		},
		{
			desc:      "have write, test against read",
			haveFlags: PFlagWrite,
			testFlags: []uint32{PFlagRead},
			ok:        false,
		},
		{
			desc:      "have read+write, test against read",
			haveFlags: PFlagRead | PFlagWrite,
			testFlags: []uint32{PFlagRead},
			ok:        true,
		},
		{
			desc:      "have read+write, test against write",
			haveFlags: PFlagRead | PFlagWrite,
			testFlags: []uint32{PFlagWrite},
			ok:        true,
		},
		{
			desc:      "have read+write, test against read+write",
			haveFlags: PFlagRead | PFlagWrite,
			testFlags: []uint32{PFlagRead, PFlagWrite},
			ok:        true,
		},
	}

	for _, tt := range tests {
		t.Log(tt.desc)

		p := &fxpOpenPkt{
			Pflags: tt.haveFlags,
		}

		if want, got := tt.ok, p.hasPflags(tt.testFlags...); want != got {
			t.Errorf("unexpected value for p.hasPflags(%#v): want: %v, got: %v",
				tt.testFlags, want, got)
		}
	}
}

func BenchmarkMarshalInit(b *testing.B) {
	for i := 0; i < b.N; i++ {
		sp(fxpInitPkt{
			Version: 3,
			Extensions: []extensionPair{
				{"posix-rename@openssh.com", "1"},
			},
		})
	}
}

func BenchmarkMarshalOpen(b *testing.B) {
	for i := 0; i < b.N; i++ {
		sp(fxpOpenPkt{
			ID:     1,
			Path:   "/home/test/some/random/path",
			Pflags: flags(os.O_RDONLY),
		})
	}
}

func BenchmarkMarshalWriteWorstCase(b *testing.B) {
	data := make([]byte, 32*1024)
	for i := 0; i < b.N; i++ {
		sp(fxpWritePkt{
			ID:     1,
			Handle: "someopaquehandle",
			Offset: 0,
			Length: uint32(len(data)),
			Data:   data,
		})
	}
}

func BenchmarkMarshalWrite1k(b *testing.B) {
	data := make([]byte, 1024)
	for i := 0; i < b.N; i++ {
		sp(fxpWritePkt{
			ID:     1,
			Handle: "someopaquehandle",
			Offset: 0,
			Length: uint32(len(data)),
			Data:   data,
		})
	}
}
