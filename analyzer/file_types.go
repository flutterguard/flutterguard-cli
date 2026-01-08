package analyzer

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	models "github.com/flutterguard/flutterguard-cli/models"
)

// analyzeFileTypes walks the full decompiled tree and aggregates by extension
func (a *Analyzer) analyzeFileTypes(root string) *models.FileTypeSummary {
	byExt := make(map[string]models.FileTypeAggregate)
	var totalFiles int
	var totalBytes int64
	var largest []models.FileInfo

	filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}

		ext := strings.ToLower(filepath.Ext(info.Name()))
		if ext == "" {
			ext = "(no extension)"
		}

		totalFiles++
		totalBytes += info.Size()

		agg := byExt[ext]
		agg.Count++
		agg.TotalBytes += info.Size()
		byExt[ext] = agg

		largest = append(largest, models.FileInfo{Name: info.Name(), Path: path, Size: info.Size()})
		if len(largest) > 10 {
			sort.Slice(largest, func(i, j int) bool { return largest[i].Size > largest[j].Size })
			largest = largest[:10]
		}

		return nil
	})

	// Build sorted top extensions
	var top []models.TopExtension
	for ext, agg := range byExt {
		top = append(top, models.TopExtension{Extension: ext, Count: agg.Count, TotalBytes: agg.TotalBytes})
	}
	sort.Slice(top, func(i, j int) bool {
		if top[i].Count == top[j].Count {
			return top[i].TotalBytes > top[j].TotalBytes
		}
		return top[i].Count > top[j].Count
	})
	if len(top) > 10 {
		top = top[:10]
	}

	avg := float64(0)
	if totalFiles > 0 {
		avg = float64(totalBytes) / float64(totalFiles)
	}

	sort.Slice(largest, func(i, j int) bool { return largest[i].Size > largest[j].Size })
	if len(largest) > 10 {
		largest = largest[:10]
	}

	return &models.FileTypeSummary{
		TotalFiles:       totalFiles,
		UniqueExtensions: len(byExt),
		TotalBytes:       totalBytes,
		AverageSizeBytes: avg,
		ByExtension:      byExt,
		TopExtensions:    top,
		LargestFiles:     largest,
	}
}
