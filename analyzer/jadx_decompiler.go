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
}

func NewJadxDecompiler(cfg *Config) *JadxDecompiler {
	return &JadxDecompiler{}
}

func (d *JadxDecompiler) Name() string {
	return "JADX Java Decompiler"
}

func (d *JadxDecompiler) Priority() int {
	return 50 // Try after direct ZIP extraction
}

func (d *JadxDecompiler) CanHandle(apkPath string) (bool, error) {
	// Check if JADX is available
	if _, err := exec.LookPath("jadx"); err != nil {
		return false, fmt.Errorf("jadx not found: %w", err)
	}
	// JADX can handle any APK
	return true, nil
}

func (d *JadxDecompiler) Decompile(ctx context.Context, apkPath, outputDir string) error {
	// Check if JADX exists
	if _, err := exec.LookPath("jadx"); err != nil {
		return fmt.Errorf("jadx not found: %w", err)
	}

	const maxRetries = 2
	baseTimeout := 30 * time.Minute

	// Retry loop with exponential backoff
	for attempt := 1; attempt <= maxRetries; attempt++ {
		// Increase timeout for each retry
		timeout := baseTimeout + (time.Duration(attempt-1) * 10 * time.Minute)
		log.Printf("JADX decompilation attempt %d/%d (timeout: %v) for %s", attempt, maxRetries, timeout, apkPath)

		cmdCtx, cancel := context.WithTimeout(ctx, timeout)

		// Run JADX with optimized flags for low-resource environments
		// -j 1: Use single thread to reduce CPU load
		// --no-res: Skip resource decoding (saves time and memory)
		// --no-imports: Skip unused imports to speed up processing
		// --deobf-use-sourcename: Faster deobfuscation
		// --deobf-min: Minimal deobfuscation for speed
		cmd := exec.CommandContext(cmdCtx, "jadx",
			"-d", outputDir,
			"-j", "1",
			"--no-res",
			"--no-imports",
			"--deobf-use-sourcename",
			"--deobf-min",
			apkPath)

		// Capture stderr for monitoring
		stderr, err := cmd.StderrPipe()
		if err != nil {
			cancel()
			if attempt < maxRetries {
				log.Printf("Failed to get stderr pipe, retrying... (attempt %d/%d)", attempt, maxRetries)
				time.Sleep(time.Duration(attempt*2) * time.Second)
				continue
			}
			return fmt.Errorf("failed to get stderr pipe: %w", err)
		}

		if err := cmd.Start(); err != nil {
			cancel()
			if attempt < maxRetries {
				log.Printf("Failed to start jadx, retrying... (attempt %d/%d): %v", attempt, maxRetries, err)
				time.Sleep(time.Duration(attempt*2) * time.Second)
				continue
			}
			return fmt.Errorf("failed to start jadx: %w", err)
		}

		// Read stderr for progress/error monitoring
		go func() {
			scanner := bufio.NewScanner(stderr)
			for scanner.Scan() {
				line := scanner.Text()
				if strings.Contains(strings.ToLower(line), "error") {
					log.Printf("JADX error: %s", line)
				}
			}
		}()

		err = cmd.Wait()
		cancel()

		if err == nil {
			log.Printf("JADX decompilation succeeded on attempt %d", attempt)
			return nil
		}

		if attempt < maxRetries {
			log.Printf("JADX attempt %d failed, retrying... Error: %v", attempt, err)
			time.Sleep(time.Duration(attempt*2) * time.Second)
			continue
		}

		return fmt.Errorf("jadx decompilation failed after %d attempts: %w", maxRetries, err)
	}

	return fmt.Errorf("jadx decompilation failed after %d attempts", maxRetries)
}
