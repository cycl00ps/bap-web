package random

import (
	"crypto/rand"
	"encoding/hex"
)

func Hex(bytes int) string {
	b := make([]byte, bytes)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}
