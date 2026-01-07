package analyzer

import (
	"archive/zip"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// ApkDirectZipDecompiler extracts APK as a ZIP file (fast, no JADX needed)
// Best for Flutter apps where we only need libapp.so and assets
type ApkDirectZipDecompiler struct{}

func NewApkDirectZipDecompiler() *ApkDirectZipDecompiler {
	return &ApkDirectZipDecompiler{}
}

func (d *ApkDirectZipDecompiler) Name() string {
	return "APK Direct ZIP Extraction"
}

func (d *ApkDirectZipDecompiler) Priority() int {
	return 100 // Try this first (fastest)
}

func (d *ApkDirectZipDecompiler) CanHandle(apkPath string) (bool, error) {
	// This can handle any valid APK since APKs are just ZIP files
	// But it's most effective for Flutter apps
	isFlutter, err := IsFlutterAPK(apkPath)
	if err != nil {
		return false, err
	}
	return isFlutter, nil
}

func (d *ApkDirectZipDecompiler) Decompile(ctx context.Context, apkPath, outputDir string) error {
	r, err := zip.OpenReader(apkPath)
	if err != nil {
		return fmt.Errorf("failed to open APK as ZIP: %w", err)
	}
	defer r.Close()

	for _, f := range r.File {
		// Check context cancellation
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		fpath := filepath.Join(outputDir, f.Name)

		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(fpath, 0755); err != nil {
				return err
			}
			continue
		}

		if err := os.MkdirAll(filepath.Dir(fpath), 0755); err != nil {
			return err
		}

		outFile, err := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err != nil {
			return err
		}

		rc, err := f.Open()
		if err != nil {
			outFile.Close()
			return err
		}

		_, err = io.Copy(outFile, rc)
		rc.Close()
		outFile.Close()
		if err != nil {
			return err
		}
	}

	return nil
}
