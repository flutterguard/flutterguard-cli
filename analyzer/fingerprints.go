package analyzer

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
)

func fileSHA256(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

func sha256String(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
