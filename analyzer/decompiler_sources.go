package analyzer

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ReadDecompiledSources reads all Java/XML source files from the decompiled folder
func (d *Decompiler) ReadDecompiledSources(decompDir string) (string, error) {
	var content strings.Builder

	err := filepath.Walk(decompDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		if info.IsDir() || (!strings.HasSuffix(path, ".java") && !strings.HasSuffix(path, ".xml")) {
			return nil
		}

		if info.Size() > 1024*1024 {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		content.WriteString(string(data))
		content.WriteString("\n\n")

		return nil
	})

	if err != nil {
		return "", err
	}

	if content.Len() == 0 {
		return "", fmt.Errorf("no Java/XML sources found")
	}

	return content.String(), nil
}
