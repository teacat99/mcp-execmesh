package security

import (
	"path/filepath"
	"strings"
)

// IsPathAllowed checks if targetPath is cleanly within any of the allowedPrefixes.
// If allowedPrefixes is empty, all valid cleaned absolute paths are permitted.
func IsPathAllowed(targetPath string, allowedPrefixes []string) bool {
	if targetPath == "" {
		return false
	}

	cleaned := filepath.Clean(targetPath)
	if !strings.HasPrefix(cleaned, "/") {
		return false
	}

	if len(allowedPrefixes) == 0 {
		return true
	}

	for _, prefix := range allowedPrefixes {
		cleanPrefix := filepath.Clean(prefix)
		if cleaned == cleanPrefix {
			return true
		}
		// Ensure prefix match is directory boundary aware
		prefixWithSlash := cleanPrefix
		if !strings.HasSuffix(prefixWithSlash, "/") {
			prefixWithSlash += "/"
		}
		if strings.HasPrefix(cleaned, prefixWithSlash) {
			return true
		}
	}

	return false
}

// CleanAndValidatePath cleans a path and checks against directory traversal.
func CleanAndValidatePath(p string, baseDir string) (string, error) {
	if p == "" {
		return baseDir, nil
	}

	cleaned := filepath.Clean(p)
	if !filepath.IsAbs(cleaned) {
		if baseDir != "" {
			cleaned = filepath.Clean(filepath.Join(baseDir, cleaned))
		} else {
			cleaned = "/" + cleaned
		}
	}

	return cleaned, nil
}
