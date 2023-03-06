# totp

Simple library with no dependencies to:

- generate [Time Based OTP](https://en.wikipedia.org/wiki/Time-based_one-time_password) codes
- parse [TOTP urls](https://github.com/google/google-authenticator/wiki/Key-Uri-Format) 

## Installation

```sh
go get -u github.com/lucasepe/totp
```

## Usage

### Generation

```go
package main

import (
	"fmt"

	"github.com/lucasepe/totp"
)

func main() {
	code, err := totp.New(totp.Options{
		Secret:   "JBSWY3DPEHPK3PXP",
		Digits:   8,
		Period:   15,
		UnixTime: 32158800000,
	})
	if err != nil {
		panic(err)
	}

	fmt.Println(code)
}
```

### URI Parsing

```go
package main

import (
	"fmt"

	"github.com/lucasepe/totp"
)

func main() {
	opts, err := totp.ParseURI("otpauth://totp/Acme?secret=IRXW4J3UEBKGK3DMEBAW46KPNZSSC")
	if err != nil {
		panic(err)
	}

	code, err := totp.New(opts)
	if err != nil {
		panic(err)
	}

	fmt.Println(code)
}
```