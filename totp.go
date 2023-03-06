package totp

import (
	"encoding/base32"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/lucasepe/totp/internal/generator"
)

// Options represents Time-based OTP.
// See https://datatracker.ietf.org/doc/html/rfc6238
type Options struct {
	Secret    string // Secret key (required)
	Digits    int    // OTP digit count (default: 6)
	Algorithm string // OTP Algorithm ("SHA1" or "SHA256" or "SHA512") (default: SHA1)
	Period    int64  // Period for which OTP is valid (seconds) (default: 30)
	UnixTime  int64  // (Optional) Unix Timestamp (default: Current unix timestamp)
}

// New generate a TOTP code.
func New(opts Options) (string, error) {
	if opts.Digits == 0 {
		opts.Digits = 6
	}

	if opts.Period == 0 {
		opts.Period = 30
	}

	return generator.Generate(generator.GenerateOptions{
		Secret:    opts.Secret,
		Counter:   computeCounter(opts.UnixTime, opts.Period),
		Digits:    opts.Digits,
		Algorithm: generator.ToHashAlgorithm(opts.Algorithm),
	})
}

// ParseKey parses a key encoded as base32, the format used by common
// two-factor authentication setup tools. Whitespace is ignored, case is
// normalized, and padding is added if required.
func ParseKey(s string) ([]byte, error) {
	clean := strings.ToUpper(strings.Join(strings.Fields(s), ""))
	if n := len(clean) % 8; n != 0 {
		clean += "========"[:8-n]
	}
	return base32.StdEncoding.DecodeString(clean)
}

func ParseURI(u string) (Options, error) {
	uri, err := url.Parse(u)
	if err != nil {
		return Options{}, err
	}

	if kind := uri.Host; !strings.EqualFold(kind, "totp") {
		return Options{}, fmt.Errorf("the only kind of the credential supported is: totp")
	}

	q := uri.Query()

	if len(q.Get("secret")) == 0 {
		return Options{}, fmt.Errorf("secret cannot be empty")
	}
	secret := strings.ToUpper(strings.Join(strings.Fields(q.Get("secret")), ""))
	if n := len(secret) % 8; n != 0 {
		secret += "========"[:8-n]
	}

	algorithm := q.Get("algorithm")

	digits := 6
	if v := q.Get("digits"); len(v) > 0 {
		digits, err = strconv.Atoi(v)
		if err != nil {
			return Options{}, err
		}
	}

	period := int64(30)
	if v := q.Get("period"); len(v) > 0 {
		period, err = strconv.ParseInt(v, 10, 64)
		if err != nil {
			return Options{}, err
		}
	}

	return Options{
		Secret:    secret,
		Digits:    digits,
		Algorithm: algorithm,
		Period:    period,
	}, nil
}

// computeCounter calculate the counter value for TOTP.
func computeCounter(unixTime int64, period int64) int64 {
	// `t0` is the epoch as specified in seconds since the Unix epoch
	// (e.g. if using Unix time, then `t0` is 0).
	var t0 int64 = 0
	// `t` is the current time in seconds since a particular epoch.
	var t int64

	if unixTime != 0 {
		t = unixTime
	} else {
		t = time.Now().Unix() - t0
	}

	return t / period
}
