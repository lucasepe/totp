package totp_test

import (
	"encoding/base32"
	"fmt"
	"testing"

	"github.com/lucasepe/totp"
)

func ExampleNew() {
	// Verify with: https://totp.danhersam.com/
	code, err := totp.New(totp.Options{
		Secret:   "JBSWY3DPEHPK3PXP",
		Digits:   8,
		Period:   15,
		UnixTime: 32158800000,
	})
	if err != nil {
		fmt.Println(err.Error())
	}

	fmt.Println(code)

	// Output: 45451783
}

func ExampleParseURI() {
	opts, err := totp.ParseURI("otpauth://totp/Acme?secret=IRXW4J3UEBKGK3DMEBAW46KPNZSSC")
	if err != nil {
		panic(err)
	}

	// This only to be sure to generate always the same code.
	opts.UnixTime = int64(32158800)

	code, err := totp.New(opts)
	if err != nil {
		panic(err)
	}

	fmt.Println(code)

	// Output: 331676
}

func TestParseURI(t *testing.T) {
	unixTime := int64(32158800)

	testcases := []struct {
		uri  string
		want string
	}{
		{
			uri:  "otpauth://totp/Acme?secret=IRXW4J3UEBKGK3DMEBAW46KPNZSSC",
			want: "331676",
		},
		{
			uri:  "otpauth://totp/Acme?secret=IRXW4J3UEBKGK3DMEBAW46KPNZSSC&digits=8&period=15",
			want: "82659370",
		},
		{
			uri:  "otpauth://totp/Acme?secret=IRXW4J3UEBKGK3DMEBAW46KPNZSSC&digits=8&period=15&algorithm=SHA256",
			want: "23552908",
		},
		{
			uri:  "otpauth://totp/Acme?secret=IRXW4J3UEBKGK3DMEBAW46KPNZSSC&digits=6&algorithm=SHA256",
			want: "408133",
		},
	}
	for _, tc := range testcases {
		opts, err := totp.ParseURI(tc.uri)
		if err != nil {
			t.Fatal(err)
		}
		opts.UnixTime = unixTime

		got, err := totp.New(opts)
		if err != nil {
			t.Fatal(err)
		}

		if got != tc.want {
			t.Errorf("expected: %s, got: %s\n", tc.want, got)
		}
	}
}

func TestTOTP(t *testing.T) {
	testcases := []struct {
		opts totp.Options
		want string
	}{
		{
			opts: totp.Options{
				Algorithm: "SHA1",
				Period:    30,
				UnixTime:  59,
				Secret:    "12345678901234567890",
				Digits:    8,
			},
			want: "94287082",
		},
		{
			opts: totp.Options{
				Algorithm: "SHA256",
				Period:    30,
				UnixTime:  59,
				Secret:    "12345678901234567890123456789012",
				Digits:    8,
			},
			want: "46119246",
		},
		{
			opts: totp.Options{
				Algorithm: "SHA512",
				Period:    30,
				UnixTime:  59,
				Secret:    "1234567890123456789012345678901234567890123456789012345678901234",
				Digits:    8,
			},
			want: "90693936",
		},
		{
			opts: totp.Options{
				Algorithm: "SHA1",
				Period:    30,
				UnixTime:  1111111109,
				Secret:    "12345678901234567890",
				Digits:    8,
			},
			want: "07081804",
		},
		{
			opts: totp.Options{
				Algorithm: "SHA256",
				Period:    30,
				UnixTime:  1111111109,
				Secret:    "12345678901234567890123456789012",
				Digits:    8,
			},
			want: "68084774",
		},
		{
			opts: totp.Options{
				Algorithm: "SHA512",
				Period:    30,
				UnixTime:  1111111109,
				Secret:    "1234567890123456789012345678901234567890123456789012345678901234",
				Digits:    8,
			},
			want: "25091201",
		},
		{
			opts: totp.Options{
				Algorithm: "SHA1",
				Period:    30,
				UnixTime:  1111111111,
				Secret:    "12345678901234567890",
				Digits:    8,
			},
			want: "14050471",
		},
		{
			opts: totp.Options{
				Algorithm: "SHA256",
				Period:    30,
				UnixTime:  1111111111,
				Secret:    "12345678901234567890123456789012",
				Digits:    8,
			},
			want: "67062674",
		},
	}

	for _, tc := range testcases {
		tc.opts.Secret = base32.StdEncoding.EncodeToString([]byte(tc.opts.Secret)) // Convert secret to base32

		got, err := totp.New(tc.opts)
		if err != nil {
			t.Fatal(err)
		}

		if got != tc.want {
			t.Errorf("expected: %s, got: %s\n", tc.want, got)
		}
	}
}
