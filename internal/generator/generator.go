package generator

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"hash"
	"math"
	"strings"
)

const (
	errInvalidAlgorithm    = "invalid algorithm. Please use any one of SHA1/SHA256/SHA512"
	errBadSecretKey        = "bad secret key: %w"
	errUnableToComputeHMAC = "unable to compute HMAC: %w"
	errNoSecretKey         = "no secret key provided"
)

type HashAlgorithm string

const (
	SHA1   HashAlgorithm = "SHA1"
	SHA256 HashAlgorithm = "SHA256"
	SHA512 HashAlgorithm = "SHA512"
)

// ToHashAlgorithm converts a string into a HashAlgorithm.
// If the string is empty returns SHA1.
func ToHashAlgorithm(s string) HashAlgorithm {
	if len(s) == 0 {
		return SHA1
	}

	return HashAlgorithm(strings.ToUpper(s))
}

type GenerateOptions struct {
	Secret    string
	Counter   int64
	Digits    int
	Algorithm HashAlgorithm
}

// Generate generates a Time or Counter based OTP code.
func Generate(opts GenerateOptions) (string, error) {
	if opts.Secret == "" {
		return "", fmt.Errorf(errNoSecretKey)
	}

	var hmacinit hash.Hash
	counterbytes := make([]byte, 8)
	binary.BigEndian.PutUint64(counterbytes, uint64(opts.Counter)) //convert counter to byte array
	secretKey, err := base32.StdEncoding.DecodeString(opts.Secret) //decode base32 secret to byte array
	if err != nil {
		return "", fmt.Errorf(errBadSecretKey, err)
	}

	switch opts.Algorithm {
	case SHA1:
		hmacinit = hmac.New(sha1.New, secretKey)
	case SHA256:
		hmacinit = hmac.New(sha256.New, secretKey)
	case SHA512:
		hmacinit = hmac.New(sha512.New, secretKey)
	default:
		return "", fmt.Errorf(errInvalidAlgorithm)
	}

	_, err = hmacinit.Write(counterbytes)
	if err != nil {
		return "", fmt.Errorf(errUnableToComputeHMAC, err)
	}

	hash := hmacinit.Sum(nil)
	offset := hash[len(hash)-1] & 0xF
	hash = hash[offset : offset+4]

	hash[0] = hash[0] & 0x7F
	decimal := binary.BigEndian.Uint32(hash)
	otp := decimal % uint32(math.Pow10(opts.Digits))

	tpl := fmt.Sprintf("%%0%dd", opts.Digits)
	return fmt.Sprintf(tpl, otp), nil

	// result := strconv.Itoa(int(otp))
	//for len(result) != opts.Digits {
	//	result = "0" + result
	//}
	//return result, nil
}
