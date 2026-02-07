package ssh_config

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func loadTestdata(tb testing.TB, name string) []byte {
	tb.Helper()
	path := filepath.Join("testdata", name)
	data, err := os.ReadFile(path)
	if err != nil {
		tb.Fatalf("read %s: %v", path, err)
	}
	return data
}

func repeatInput(data []byte, count int) []byte {
	if count <= 1 {
		return append([]byte(nil), data...)
	}
	return bytes.Repeat(data, count)
}

func BenchmarkDecodeBytes(b *testing.B) {
	small := loadTestdata(b, "config4")
	medium := loadTestdata(b, "config1")
	large := repeatInput(medium, 20)

	cases := []struct {
		name string
		data []byte
	}{
		{name: "small", data: small},
		{name: "medium", data: medium},
		{name: "large", data: large},
	}

	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(tc.data)))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := DecodeBytes(tc.data); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkResolve(b *testing.B) {
	data := loadTestdata(b, "config3")
	cfg, err := DecodeBytes(data)
	if err != nil {
		b.Fatal(err)
	}
	if _, err := loadClientSpec(); err != nil {
		b.Fatal(err)
	}
	ctx := Context{
		HostArg:   "10.1.2.3",
		LocalUser: "bench",
	}

	cases := []struct {
		name string
		opts []ResolveOption
	}{
		{name: "default", opts: nil},
		{name: "strict", opts: []ResolveOption{Strict()}},
	}

	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := cfg.Resolve(ctx, tc.opts...); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
