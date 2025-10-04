package session

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

func Fingerprint(data any, extras ...string) string {
	hasher := sha256.New()
	if data != nil {
		if b, err := json.Marshal(data); err == nil {
			hasher.Write(b)
		}
	}
	for _, v := range extras {
		hasher.Write([]byte(v))
	}
	return hex.EncodeToString(hasher.Sum(nil))
}
