package analyzer

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"time"
)

// JadxDecompiler uses JADX to decompile APKs to Java source code
// Best for non-Flutter apps or when you need full Java source
type JadxDecompiler struct {
	cfg *Config
}

func NewJadxDecompiler(cfg *Config) *JadxDecompiler {
	return &JadxDecompiler{cfg: cfg}
}

func (d *JadxDecompiler) Name() string {
	return "JADX Java Decompiler"
}

func (d *JadxDecompiler) Priority() int {
	return 50
}

func (d *JadxDecompiler) CanHandle(apkPath string) (bool, error) {

	if _, err := exec.LookPath("jadx"); err != nil {
		return false, fmt.Errorf("jadx not found: %w", err)
	}

	return true, nil
}

func (d *JadxDecompiler) Decompile(ctx context.Context, apkPath, outputDir string) error {

	if _, err := exec.LookPath("jadx"); err != nil {
		return fmt.Errorf("jadx not found: %w", err)
	}

	const maxRetries = 2
	baseTimeout := 30 * time.Minute

	for attempt := 1; attempt <= maxRetries; attempt++ {

		timeout := baseTimeout + (time.Duration(attempt-1) * 10 * time.Minute)
		if d.cfg.Verbose {
			log.Printf("JADX decompilation attempt %d/%d (timeout: %v) for %s", attempt, maxRetries, timeout, apkPath)
		} else if attempt == 1 {
			log.Printf("→ Decompiling APK with JADX...")
		}

		cmdCtx, cancel := context.WithTimeout(ctx, timeout)

		cmd := exec.CommandContext(cmdCtx, "jadx",
			"-d", outputDir,
			"-j", "1",
			"--no-res",
			"--no-imports",
			"--deobf-use-sourcename",
			"--deobf-min",
			apkPath)

		stderr, err := cmd.StderrPipe()
		if err != nil {
			cancel()
			if attempt < maxRetries {
				if d.cfg.Verbose {
					log.Printf("Failed to get stderr pipe, retrying... (attempt %d/%d)", attempt, maxRetries)
				}
				time.Sleep(time.Duration(attempt*2) * time.Second)
				continue
			}
			return fmt.Errorf("failed to get stderr pipe: %w", err)
		}

		if err := cmd.Start(); err != nil {
			cancel()
			if attempt < maxRetries {
				if d.cfg.Verbose {
					log.Printf("Failed to start jadx, retrying... (attempt %d/%d): %v", attempt, maxRetries, err)
				}
				time.Sleep(time.Duration(attempt*2) * time.Second)
				continue
			}
			return fmt.Errorf("failed to start jadx: %w", err)
		}

		go func() {
			scanner := bufio.NewScanner(stderr)
			for scanner.Scan() {
				line := scanner.Text()
				if d.cfg.Verbose && strings.Contains(strings.ToLower(line), "error") {
					log.Printf("JADX error: %s", line)
				}
			}
		}()

		err = cmd.Wait()
		cancel()

		if err == nil {
			if d.cfg.Verbose {
				log.Printf("JADX decompilation succeeded on attempt %d", attempt)
			} else {
				log.Printf("✓ Decompilation completed successfully")
			}
			return nil
		}

		if attempt < maxRetries {
			if d.cfg.Verbose {
				log.Printf("JADX attempt %d failed, retrying... Error: %v", attempt, err)
			} else {
				log.Printf("↻ Retrying decompilation (attempt %d/%d)...", attempt+1, maxRetries)
			}
			time.Sleep(time.Duration(attempt*2) * time.Second)
			continue
		}

		return fmt.Errorf("jadx decompilation failed after %d attempts: %w", maxRetries, err)
	}

	return fmt.Errorf("jadx decompilation failed after %d attempts", maxRetries)
}
