package bag

import (
	"crypto/rand"
	"encoding/base64"
)

func NewRandText() string {
	n := make([]byte, 16)
	rand.Read(n)
	return base64.StdEncoding.EncodeToString(n)
}
