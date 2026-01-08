package analyzer

import (
	"fmt"
	"os"
	"path/filepath"
	"io"

	models "github.com/flutterguard/flutterguard-cli/models"
)

// SaveResults saves all extracted files to the report directory
func (a *Analyzer) SaveResults(analysisID, decompDir, reportDir string, results *models.Results) error {
	analysisDir := filepath.Join(reportDir, analysisID)
	if err := os.MkdirAll(analysisDir, 0755); err != nil {
		return err
	}

	if err := a.saveFiles(decompDir, analysisDir, filepath.Join("assets", "env_files"), results.EnvFiles); err != nil {
		return err
	}
	if err := a.saveFiles(decompDir, analysisDir, filepath.Join("assets", "config_files"), results.ConfigFiles); err != nil {
		return err
	}
	if err := a.saveFiles(decompDir, analysisDir, filepath.Join("assets", "content_files"), results.ContentFiles); err != nil {
		return err
	}
	if err := a.saveFiles(decompDir, analysisDir, filepath.Join("assets", "visual_assets"), results.VisualAssets); err != nil {
		return err
	}

	return nil
}

func (a *Analyzer) saveFiles(sourceBase, targetBase, category string, files []models.FileInfo) error {
	if len(files) == 0 {
		return nil
	}

	categoryDir := filepath.Join(targetBase, category)
	if err := os.MkdirAll(categoryDir, 0755); err != nil {
		return err
	}

	for _, file := range files {
		srcPath := file.Path
		dstPath := filepath.Join(categoryDir, file.Name)

		if err := copyFile(srcPath, dstPath); err != nil {
			return fmt.Errorf("failed to copy %s: %w", file.Name, err)
		}
	}

	return nil
}

func copyFile(src, dst string) error {
	source, err := os.Open(src)
	if err != nil {
		return err
	}
	defer source.Close()

	destination, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destination.Close()

	_, err = io.Copy(destination, source)
	return err
}
