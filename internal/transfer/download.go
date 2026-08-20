package transfer

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/pkg/sftp"
	"github.com/teacat/mcp-execmesh/internal/security"
)

func safeDownloadFilename(remotePath string) string {
	base := path.Base(remotePath)
	base = strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-' {
			return r
		}
		return '_'
	}, base)
	if base == "" || base == "." {
		return "download.bin"
	}
	return base
}

// resolveRemoteFilePath resolves symlinks and ensures the final path stays within allowed_paths.
func resolveRemoteFilePath(client *sftp.Client, remotePath string, allowedPaths []string) (string, error) {
	const maxLinks = 8
	current := remotePath
	for i := 0; i < maxLinks; i++ {
		fi, err := client.Lstat(current)
		if err != nil {
			return "", err
		}
		if fi.Mode()&os.ModeSymlink == 0 {
			if fi.IsDir() {
				return "", fmt.Errorf("remote path %q is a directory, not a file", remotePath)
			}
			clean := filepath.Clean(current)
			if !security.IsPathAllowed(clean, allowedPaths) {
				return "", fmt.Errorf("%w: %q", ErrPathDisallowed, clean)
			}
			return clean, nil
		}
		target, err := client.ReadLink(current)
		if err != nil {
			return "", err
		}
		if !filepath.IsAbs(target) {
			target = filepath.Clean(filepath.Join(filepath.Dir(current), target))
		} else {
			target = filepath.Clean(target)
		}
		current = target
	}
	return "", fmt.Errorf("symlink depth exceeded for %q", remotePath)
}
