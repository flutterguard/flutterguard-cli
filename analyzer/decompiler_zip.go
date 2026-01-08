package analyzer

import (
	"archive/zip"
	"io"
	"os"
	"path/filepath"
)

// createDecompZip creates a zip file of the decompiled folder
func (a *Analyzer) createDecompZip(decompDir string) (string, error) {
	zipPath := decompDir + ".zip"

	zipFile, err := os.Create(zipPath)
	if err != nil {
		return "", err
	}
	defer zipFile.Close()

	zipWriter := zip.NewWriter(zipFile)
	defer zipWriter.Close()

	err = filepath.Walk(decompDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		relPath, err := filepath.Rel(decompDir, path)
		if err != nil {
			return err
		}

		if info.IsDir() {

			_, err := zipWriter.Create(relPath + "/")
			return err
		}

		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()

		writer, err := zipWriter.Create(relPath)
		if err != nil {
			return err
		}

		_, err = io.Copy(writer, file)
		return err
	})

	if err != nil {
		os.Remove(zipPath)
		return "", err
	}

	return zipPath, nil
}
