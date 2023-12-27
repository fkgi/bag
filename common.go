package bag

import (
	"crypto/rand"
	"encoding/base64"
	"time"
)

var (
	qop         = []string{"auth-int"}
	expiration  = time.Second * 10
	productName = "bag"
)

func NewRandText() string {
	n := make([]byte, 16)
	rand.Read(n)
	return base64.StdEncoding.EncodeToString(n)
}
