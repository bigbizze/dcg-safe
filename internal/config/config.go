// Package config loads and initializes dcg-safe's capture policy.
package config

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
	dcgsafe "github.com/bigbizze/dcg-safe"
	"github.com/bigbizze/dcg-safe/internal/account"
	"golang.org/x/sys/unix"
)

const (
	Schema         = 1
	MaxConfigBytes = 64 * 1024
	DirName        = ".dcg-safe"
	FileName       = "config.toml"
)

// Policy is a syntactically validated capture policy.
type Policy struct {
	Roots      []string
	ConfigPath string
	Defaults   bool
}

type diskConfig struct {
	Schema       int      `toml:"schema"`
	AllowedRoots []string `toml:"allowed_roots"`
}

// Path returns the fixed config path for id. It never consults HOME.
func Path(id account.Identity) string {
	return filepath.Join(id.Home, DirName, FileName)
}

// Load reads the secure on-disk policy, or the embedded defaults if the file
// is absent. An existing malformed or insecure policy fails closed.
func Load(id account.Identity) (Policy, error) {
	dirPath := filepath.Join(id.Home, DirName)
	dirFD, err := unix.Open(dirPath, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return parsePolicy([]byte(dcgsafe.DefaultConfig), id, "", true)
		}
		return Policy{}, fmt.Errorf("open config directory %s: %w", dirPath, err)
	}
	defer unix.Close(dirFD)

	if err := validateDirectoryFD(dirFD, id.UID, "config directory"); err != nil {
		return Policy{}, err
	}
	fileFD, err := unix.Openat(dirFD, FileName, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return parsePolicy([]byte(dcgsafe.DefaultConfig), id, "", true)
		}
		return Policy{}, fmt.Errorf("open config file %s: %w", Path(id), err)
	}
	file := os.NewFile(uintptr(fileFD), Path(id))
	if file == nil {
		unix.Close(fileFD)
		return Policy{}, errors.New("open config file: invalid descriptor")
	}
	defer file.Close()

	var stat unix.Stat_t
	if err := unix.Fstat(fileFD, &stat); err != nil {
		return Policy{}, fmt.Errorf("stat config file: %w", err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return Policy{}, errors.New("config file must be a regular file")
	}
	if int(stat.Uid) != id.UID {
		return Policy{}, fmt.Errorf("config file must be owned by effective UID %d", id.UID)
	}
	if stat.Mode&0o022 != 0 {
		return Policy{}, errors.New("config file must not be group- or other-writable")
	}
	if stat.Size > MaxConfigBytes {
		return Policy{}, fmt.Errorf("config file exceeds %d bytes", MaxConfigBytes)
	}
	body, err := io.ReadAll(io.LimitReader(file, MaxConfigBytes+1))
	if err != nil {
		return Policy{}, fmt.Errorf("read config file: %w", err)
	}
	if len(body) > MaxConfigBytes {
		return Policy{}, fmt.Errorf("config file exceeds %d bytes", MaxConfigBytes)
	}
	return parsePolicy(body, id, Path(id), false)
}

// Init creates the fixed config with embedded default bytes. Existing valid
// files are an idempotent success; existing invalid files are never changed.
func Init(id account.Identity) (created bool, err error) {
	configPath := Path(id)
	if _, lstatErr := os.Lstat(configPath); lstatErr == nil {
		_, loadErr := Load(id)
		return false, loadErr
	} else if !errors.Is(lstatErr, os.ErrNotExist) {
		return false, fmt.Errorf("inspect config file: %w", lstatErr)
	}

	dirPath := filepath.Join(id.Home, DirName)
	madeDir := false
	if err := os.Mkdir(dirPath, 0o700); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return false, fmt.Errorf("create config directory: %w", err)
		}
	} else {
		madeDir = true
		if err := os.Chmod(dirPath, 0o700); err != nil {
			return false, fmt.Errorf("set config directory mode: %w", err)
		}
	}

	dirFD, err := unix.Open(dirPath, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return false, fmt.Errorf("open config directory: %w", err)
	}
	defer unix.Close(dirFD)
	if err := validateDirectoryFD(dirFD, id.UID, "config directory"); err != nil {
		return false, err
	}
	if madeDir {
		if err := unix.Fchmod(dirFD, 0o700); err != nil {
			return false, fmt.Errorf("set config directory mode: %w", err)
		}
	}

	fileFD, err := unix.Openat(
		dirFD,
		FileName,
		unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0o600,
	)
	if err != nil {
		if errors.Is(err, unix.EEXIST) {
			_, loadErr := Load(id)
			return false, loadErr
		}
		return false, fmt.Errorf("create config file: %w", err)
	}
	keep := false
	defer func() {
		if !keep {
			_ = unix.Unlinkat(dirFD, FileName, 0)
		}
	}()
	if err := unix.Fchmod(fileFD, 0o600); err != nil {
		unix.Close(fileFD)
		return false, fmt.Errorf("set config file mode: %w", err)
	}
	if err := writeAll(fileFD, []byte(dcgsafe.DefaultConfig)); err != nil {
		unix.Close(fileFD)
		return false, fmt.Errorf("write config file: %w", err)
	}
	if err := unix.Fsync(fileFD); err != nil {
		unix.Close(fileFD)
		return false, fmt.Errorf("sync config file: %w", err)
	}
	if err := unix.Close(fileFD); err != nil {
		return false, fmt.Errorf("close config file: %w", err)
	}
	if err := unix.Fsync(dirFD); err != nil {
		return false, fmt.Errorf("sync config directory: %w", err)
	}
	keep = true
	return true, nil
}

func parsePolicy(body []byte, id account.Identity, configPath string, defaults bool) (Policy, error) {
	var raw diskConfig
	metadata, err := toml.Decode(string(body), &raw)
	if err != nil {
		return Policy{}, fmt.Errorf("parse config: %w", err)
	}
	if undecoded := metadata.Undecoded(); len(undecoded) != 0 {
		keys := make([]string, 0, len(undecoded))
		for _, key := range undecoded {
			keys = append(keys, key.String())
		}
		return Policy{}, fmt.Errorf("unknown config keys: %s", strings.Join(keys, ", "))
	}
	if raw.Schema != Schema {
		return Policy{}, fmt.Errorf("unsupported config schema %d (want %d)", raw.Schema, Schema)
	}
	if len(raw.AllowedRoots) == 0 {
		return Policy{}, errors.New("allowed_roots must not be empty")
	}
	roots := make([]string, 0, len(raw.AllowedRoots))
	seen := make(map[string]struct{}, len(raw.AllowedRoots))
	for index, value := range raw.AllowedRoots {
		root, err := normalizeRoot(value, id.Home)
		if err != nil {
			return Policy{}, fmt.Errorf("allowed_roots[%d]: %w", index, err)
		}
		if _, ok := seen[root]; ok {
			return Policy{}, fmt.Errorf("duplicate normalized root %q", root)
		}
		seen[root] = struct{}{}
		roots = append(roots, root)
	}
	return Policy{Roots: roots, ConfigPath: configPath, Defaults: defaults}, nil
}

func normalizeRoot(value, home string) (string, error) {
	if value == "" {
		return "", errors.New("root must not be empty")
	}
	if strings.IndexByte(value, 0) >= 0 {
		return "", errors.New("root contains NUL")
	}
	if strings.Contains(value, "$") {
		return "", errors.New("environment references are not allowed")
	}
	if strings.ContainsAny(value, "*?[") {
		return "", errors.New("globs are not allowed")
	}
	if strings.Contains(value, string(filepath.Separator)+string(filepath.Separator)) {
		return "", errors.New("repeated path separators are not allowed")
	}
	switch {
	case strings.HasPrefix(value, "~/"):
		remainder := strings.TrimPrefix(value, "~/")
		if strings.Contains(remainder, "~") {
			return "", errors.New("only a leading ~/ expansion is allowed")
		}
		value = filepath.Join(home, remainder)
	case strings.Contains(value, "~"):
		return "", errors.New("only a leading ~/ expansion is allowed")
	case !filepath.IsAbs(value):
		return "", errors.New("root must be absolute or begin with ~/")
	}
	for _, component := range strings.Split(value, string(filepath.Separator)) {
		if component == "." || component == ".." {
			return "", errors.New("traversal components are not allowed")
		}
	}
	root := filepath.Clean(value)
	if !filepath.IsAbs(root) {
		return "", errors.New("normalized root must be absolute")
	}
	return root, nil
}

func validateDirectoryFD(fd, uid int, label string) error {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return fmt.Errorf("stat %s: %w", label, err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR {
		return fmt.Errorf("%s must be a real directory", label)
	}
	if int(stat.Uid) != uid {
		return fmt.Errorf("%s must be owned by effective UID %d", label, uid)
	}
	if stat.Mode&0o022 != 0 {
		return fmt.Errorf("%s must not be group- or other-writable", label)
	}
	return nil
}

func writeAll(fd int, body []byte) error {
	for len(body) > 0 {
		n, err := unix.Write(fd, body)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		body = body[n:]
	}
	return nil
}
