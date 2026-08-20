package knownhosts

import (
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	"github.com/teacat/mcp-execmesh/internal/config"
	"golang.org/x/crypto/ssh"
)

type Entry struct {
	Name        string `json:"name"`
	Algorithm   string `json:"algorithm"`
	Fingerprint string `json:"fingerprint"`
}

func ParseFile(path string) ([]Entry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []Entry
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		name, algo, b64 := fields[0], fields[1], fields[2]
		raw, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			continue
		}
		pk, err := ssh.ParsePublicKey(raw)
		if err != nil {
			continue
		}
		out = append(out, Entry{
			Name:        name,
			Algorithm:   algo,
			Fingerprint: ssh.FingerprintSHA256(pk),
		})
	}
	return out, nil
}

func HasName(entries []Entry, name string) bool {
	for _, e := range entries {
		if e.Name == name {
			return true
		}
	}
	return false
}

func FilterByName(entries []Entry, name string) []Entry {
	var out []Entry
	for _, e := range entries {
		if e.Name == name {
			out = append(out, e)
		}
	}
	return out
}

func AppendKey(path, name, algorithm, publicKeyB64 string) error {
	name = strings.TrimSpace(name)
	algorithm = strings.TrimSpace(algorithm)
	publicKeyB64 = strings.TrimSpace(publicKeyB64)
	if name == "" || algorithm == "" || publicKeyB64 == "" {
		return fmt.Errorf("name, algorithm, and public_key are required")
	}
	raw, err := base64.StdEncoding.DecodeString(publicKeyB64)
	if err != nil {
		return fmt.Errorf("invalid public_key encoding: %w", err)
	}
	if _, err := ssh.ParsePublicKey(raw); err != nil {
		return fmt.Errorf("invalid public_key: %w", err)
	}
	line := fmt.Sprintf("%s %s %s\n", name, algorithm, publicKeyB64)
	existing, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	for _, l := range strings.Split(string(existing), "\n") {
		if strings.TrimSpace(l) == strings.TrimSpace(line) {
			return nil
		}
	}
	return config.WriteFileInPlace(path, append(existing, []byte(line)...), 0644)
}

func RemoveName(path, name string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var keep []string
	removed := 0
	for _, line := range strings.Split(string(data), "\n") {
		trim := strings.TrimSpace(line)
		if trim == "" {
			keep = append(keep, line)
			continue
		}
		fields := strings.Fields(trim)
		if len(fields) >= 1 && fields[0] == name {
			removed++
			continue
		}
		keep = append(keep, line)
	}
	if removed == 0 {
		return fmt.Errorf("no known_hosts entries for %q", name)
	}
	out := strings.Join(keep, "\n")
	if !strings.HasSuffix(out, "\n") {
		out += "\n"
	}
	return config.WriteFileInPlace(path, []byte(out), 0644)
}
