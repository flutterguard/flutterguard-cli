package analyzer

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	models "github.com/flutterguard/flutterguard-cli/models"
)

// EnvExtractor extracts .env files and their contents
type EnvExtractor struct {
	envFilePatterns []string
	sensitiveKeys   map[string]bool
}

func NewEnvExtractor() *EnvExtractor {
	return &EnvExtractor{
		envFilePatterns: []string{
			".env",
			".env.local",
			".env.development",
			".env.production",
			".env.staging",
			".env.test",
			".env.example",
			".env.sample",
		},
		sensitiveKeys: map[string]bool{
			"password":      true,
			"secret":        true,
			"key":           true,
			"token":         true,
			"api_key":       true,
			"apikey":        true,
			"private_key":   true,
			"private":       true,
			"credentials":   true,
			"auth":          true,
			"access_token":  true,
			"client_secret": true,
		},
	}
}

// ExtractEnvFiles finds and extracts .env files from decompiled directory
func (ee *EnvExtractor) ExtractEnvFiles(decompDir string) []models.EnvFileData {
	var envData []models.EnvFileData

	filepath.Walk(decompDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}

		filename := strings.ToLower(info.Name())
		isEnvFile := false
		for _, pattern := range ee.envFilePatterns {
			if filename == pattern {
				isEnvFile = true
				break
			}
		}

		if !isEnvFile {
			return nil
		}

		variables := ee.extractVariables(path)
		if len(variables) > 0 {
			envData = append(envData, models.EnvFileData{
				FilePath:  path,
				Variables: variables,
			})
		}

		return nil
	})

	return envData
}

// extractVariables parses env file and extracts key-value pairs
func (ee *EnvExtractor) extractVariables(filePath string) []models.EnvVariable {
	file, err := os.Open(filePath)
	if err != nil {
		return nil
	}
	defer file.Close()

	var variables []models.EnvVariable
	scanner := bufio.NewScanner(file)
	lineRegex := regexp.MustCompile(`^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$`)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		matches := lineRegex.FindStringSubmatch(line)
		if len(matches) >= 3 {
			key := matches[1]
			value := matches[2]

			value = strings.Trim(value, `"'`)

			isSensitive := ee.isSensitiveKey(key)

			variable := models.EnvVariable{
				Key:      key,
				Value:    value,
				IsMasked: isSensitive,
				FilePath: filePath,
			}

			if isSensitive && len(value) > 8 {
				variable.Value = value[:4] + "***" + value[len(value)-2:]
			} else if isSensitive {
				variable.Value = "***"
			}

			variables = append(variables, variable)
		}
	}

	return variables
}

// isSensitiveKey checks if a key name suggests sensitive data
func (ee *EnvExtractor) isSensitiveKey(key string) bool {
	keyLower := strings.ToLower(key)

	for sensitivePattern := range ee.sensitiveKeys {
		if strings.Contains(keyLower, sensitivePattern) {
			return true
		}
	}

	return false
}
