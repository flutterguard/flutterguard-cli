package analyzer

import (
	"os"
	"path/filepath"
	"strings"

	models "github.com/flutterguard/flutterguard-cli/models"
)

func (a *Analyzer) scanForFiles(dir string, extensions []string, assetsOnly bool) []models.FileInfo {
	var files []models.FileInfo

	filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}

		hasExt := false
		for _, ext := range extensions {
			if strings.HasSuffix(strings.ToLower(info.Name()), ext) {
				hasExt = true
				break
			}
		}

		if !hasExt {
			return nil
		}

		if assetsOnly {
			lowerPath := strings.ToLower(strings.ReplaceAll(path, "\\", "/"))
			inAssets := strings.Contains(lowerPath, "assets")
			inAndroidRes := strings.Contains(lowerPath, "/res/mipmap") || strings.Contains(lowerPath, "/res/drawable")
			if !inAssets && !inAndroidRes {
				return nil
			}
		}

		files = append(files, models.FileInfo{
			Name: info.Name(),
			Path: path,
			Size: info.Size(),
		})

		return nil
	})

	return files
}

func (a *Analyzer) computeAssetSizes(files []models.FileInfo) *models.AssetSizeBreakdown {
	var s models.AssetSizeBreakdown
	for _, f := range files {
		name := strings.ToLower(f.Name)
		switch {
		case strings.HasSuffix(name, ".png") || strings.HasSuffix(name, ".jpg") || strings.HasSuffix(name, ".jpeg") || strings.HasSuffix(name, ".gif") || strings.HasSuffix(name, ".svg") || strings.HasSuffix(name, ".webp") || strings.HasSuffix(name, ".bmp") || strings.HasSuffix(name, ".ico"):
			s.ImagesBytes += f.Size
		case strings.HasSuffix(name, ".ttf") || strings.HasSuffix(name, ".otf") || strings.HasSuffix(name, ".woff") || strings.HasSuffix(name, ".woff2"):
			s.FontsBytes += f.Size
		case strings.HasSuffix(name, ".mp3") || strings.HasSuffix(name, ".wav") || strings.HasSuffix(name, ".aac"):
			s.AudioBytes += f.Size
		case strings.HasSuffix(name, ".mp4") || strings.HasSuffix(name, ".avi") || strings.HasSuffix(name, ".mov") || strings.HasSuffix(name, ".webm"):
			s.VideoBytes += f.Size
		default:
			s.OtherBytes += f.Size
		}
	}
	return &s
}

func (a *Analyzer) findAppIcon(assets []models.FileInfo) string {
	isImage := func(name string) bool {
		return strings.HasSuffix(name, ".png") || strings.HasSuffix(name, ".webp") ||
			strings.HasSuffix(name, ".jpg") || strings.HasSuffix(name, ".jpeg") ||
			strings.HasSuffix(name, ".ico") || strings.HasSuffix(name, ".svg")
	}

	densityRank := map[string]int{
		"xxxhdpi": 6,
		"xxhdpi":  5,
		"xhdpi":   4,
		"hdpi":    3,
		"mdpi":    2,
		"ldpi":    1,
	}

	iconPatterns := []string{"ic_launcher", "ic_launcher_round", "icon", "app_icon", "logo", "app_logo", "ic_app", "launcher"}

	normalizePath := func(p string) string {
		return strings.ToLower(strings.ReplaceAll(p, "\\", "/"))
	}

	// Phase 1: strict launcher pick — mipmap ic_launcher* at highest density
	type launcherCand struct {
		info    models.FileInfo
		density int
	}
	bestLauncher := launcherCand{}

	for _, asset := range assets {
		name := strings.ToLower(asset.Name)
		path := normalizePath(asset.Path)

		if asset.Size < 1024 || !isImage(name) {
			continue
		}
		if !strings.Contains(path, "/res/mipmap") {
			continue
		}
		if !strings.Contains(name, "ic_launcher") {
			continue
		}

		d := 0
		for k, v := range densityRank {
			if strings.Contains(path, k) {
				d = v
				break
			}
		}
		if d == 0 {
			d = 1
		}

		if d > bestLauncher.density || (d == bestLauncher.density && asset.Size > bestLauncher.info.Size) {
			bestLauncher = launcherCand{info: asset, density: d}
		}
	}

	if bestLauncher.info.Path != "" {
		return bestLauncher.info.Path
	}

	// Phase 2: weighted heuristic across all assets
	type candidate struct {
		info  models.FileInfo
		score int
	}
	best := candidate{}

	for _, asset := range assets {
		name := strings.ToLower(asset.Name)
		path := normalizePath(asset.Path)

		if asset.Size < 1024 || !isImage(name) {
			continue
		}

		score := 0

		if strings.Contains(path, "/res/mipmap") {
			score += 50
		} else if strings.Contains(path, "/res/drawable") {
			score += 30
		} else if strings.Contains(path, "assets") {
			score += 10
		}

		for _, pattern := range iconPatterns {
			if strings.Contains(name, pattern) {
				score += 25
				break
			}
		}

		for k, v := range densityRank {
			if strings.Contains(path, k) {
				score += v * 3
				break
			}
		}

		switch {
		case strings.HasSuffix(name, ".png"):
			score += 8
		case strings.HasSuffix(name, ".webp"):
			score += 6
		case strings.HasSuffix(name, ".jpg"), strings.HasSuffix(name, ".jpeg"):
			score += 3
		}

		if score > best.score || (score == best.score && asset.Size > best.info.Size) {
			best = candidate{info: asset, score: score}
		}
	}

	if best.info.Path != "" {
		return best.info.Path
	}

	// Phase 3: fallback — largest PNG/WEBP
	var fallback models.FileInfo
	for _, asset := range assets {
		lowerName := strings.ToLower(asset.Name)
		if (strings.HasSuffix(lowerName, ".png") || strings.HasSuffix(lowerName, ".webp")) && asset.Size > fallback.Size {
			fallback = asset
		}
	}

	if fallback.Path != "" {
		return fallback.Path
	}

	return ""
}
