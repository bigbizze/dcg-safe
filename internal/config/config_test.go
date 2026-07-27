package config

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	dcgsafe "github.com/bigbizze/dcg-safe"
	"github.com/bigbizze/dcg-safe/internal/account"
)

func TestLoadUsesEmbeddedDefaultsAndAccountHome(t *testing.T) {
	identity := account.Identity{UID: os.Geteuid(), Home: t.TempDir()}
	t.Setenv("HOME", filepath.Join(t.TempDir(), "poison"))
	policy, err := Load(identity)
	if err != nil {
		t.Fatal(err)
	}
	if !policy.Defaults || policy.ConfigPath != "" {
		t.Fatalf("unexpected source: %+v", policy)
	}
	want := []string{
		"/tmp",
		filepath.Join(identity.Home, "tmp"),
		filepath.Join(identity.Home, "WebstormProjects"),
		filepath.Join(identity.Home, "Documents"),
	}
	if strings.Join(policy.Roots, "\n") != strings.Join(want, "\n") {
		t.Fatalf("roots:\n%q\nwant:\n%q", policy.Roots, want)
	}
	for _, root := range policy.Roots {
		if strings.Contains(root, os.Getenv("HOME")) {
			t.Fatalf("root used poisoned HOME: %s", root)
		}
	}
}

func TestInitCreatesExactModesAndIsIdempotent(t *testing.T) {
	identity := account.Identity{UID: os.Geteuid(), Home: t.TempDir()}
	oldMask := setUmask(0o777)
	created, err := Init(identity)
	setUmask(oldMask)
	if err != nil {
		t.Fatal(err)
	}
	if !created {
		t.Fatal("first init did not report creation")
	}
	assertMode(t, filepath.Join(identity.Home, DirName), 0o700)
	assertMode(t, Path(identity), 0o600)
	body, err := os.ReadFile(Path(identity))
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != dcgsafe.DefaultConfig {
		t.Fatalf("config bytes differ from embedded source:\n%s", body)
	}
	before := append([]byte(nil), body...)
	created, err = Init(identity)
	if err != nil {
		t.Fatal(err)
	}
	if created {
		t.Fatal("idempotent init reported creation")
	}
	after, err := os.ReadFile(Path(identity))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("idempotent init changed the config")
	}
}

func TestInitReportsInvalidExistingFileUnchanged(t *testing.T) {
	identity := account.Identity{UID: os.Geteuid(), Home: t.TempDir()}
	body := []byte("schema = 99\nallowed_roots = [\"/tmp\"]\n")
	writeConfig(t, identity, body, 0o700, 0o600)
	created, err := Init(identity)
	if err == nil || created {
		t.Fatalf("Init() = created %v, err %v", created, err)
	}
	after, readErr := os.ReadFile(Path(identity))
	if readErr != nil {
		t.Fatal(readErr)
	}
	if !bytes.Equal(body, after) {
		t.Fatal("invalid existing config was modified")
	}
}

func TestStrictConfigRejections(t *testing.T) {
	tests := map[string]string{
		"unknown key": `schema = 1
allowed_roots = ["/tmp"]
extra = true
`,
		"wrong schema": `schema = 2
allowed_roots = ["/tmp"]
`,
		"duplicate normalized": `schema = 1
allowed_roots = ["/tmp", "/tmp/"]
`,
		"relative": `schema = 1
allowed_roots = ["tmp"]
`,
		"environment": `schema = 1
allowed_roots = ["$HOME/tmp"]
`,
		"glob": `schema = 1
allowed_roots = ["/tmp/*"]
`,
		"other tilde": `schema = 1
allowed_roots = ["~other/tmp"]
`,
		"embedded tilde": `schema = 1
allowed_roots = ["~/tmp~copy"]
`,
		"traversal": `schema = 1
allowed_roots = ["/tmp/../tmp"]
`,
		"repeated separator": `schema = 1
allowed_roots = ["/tmp//capture"]
`,
		"repeated separator after tilde": `schema = 1
allowed_roots = ["~//capture"]
`,
		"empty roots": `schema = 1
allowed_roots = []
`,
		"duplicate key": `schema = 1
schema = 1
allowed_roots = ["/tmp"]
`,
	}
	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			identity := account.Identity{UID: os.Geteuid(), Home: t.TempDir()}
			writeConfig(t, identity, []byte(body), 0o700, 0o600)
			if _, err := Load(identity); err == nil {
				t.Fatal("Load unexpectedly accepted invalid config")
			}
		})
	}
}

func TestConfigMaximumSize(t *testing.T) {
	identity := account.Identity{UID: os.Geteuid(), Home: t.TempDir()}
	body := append([]byte("schema = 1\nallowed_roots = [\"/tmp\"]\n#"), bytes.Repeat([]byte{'x'}, MaxConfigBytes)...)
	writeConfig(t, identity, body, 0o700, 0o600)
	_, err := Load(identity)
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("Load error = %v, want size rejection", err)
	}
}

func TestConfigSecurityChecks(t *testing.T) {
	tests := []struct {
		name     string
		dirMode  os.FileMode
		fileMode os.FileMode
		fakeUID  bool
	}{
		{name: "group writable directory", dirMode: 0o720, fileMode: 0o600},
		{name: "other writable directory", dirMode: 0o702, fileMode: 0o600},
		{name: "group writable file", dirMode: 0o700, fileMode: 0o620},
		{name: "other writable file", dirMode: 0o700, fileMode: 0o602},
		{name: "foreign directory", dirMode: 0o700, fileMode: 0o600, fakeUID: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			identity := account.Identity{UID: os.Geteuid(), Home: t.TempDir()}
			writeConfig(t, identity, []byte(dcgsafe.DefaultConfig), test.dirMode, test.fileMode)
			if test.fakeUID {
				identity.UID++
			}
			if _, err := Load(identity); err == nil {
				t.Fatal("Load unexpectedly accepted insecure config")
			}
		})
	}
}

func TestConfigRejectsSymlinkFileAndDirectory(t *testing.T) {
	t.Run("file", func(t *testing.T) {
		identity := account.Identity{UID: os.Geteuid(), Home: t.TempDir()}
		dir := filepath.Join(identity.Home, DirName)
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(identity.Home, "target.toml")
		if err := os.WriteFile(target, []byte(dcgsafe.DefaultConfig), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, Path(identity)); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(identity); err == nil {
			t.Fatal("Load accepted symlinked config")
		}
	})
	t.Run("directory", func(t *testing.T) {
		identity := account.Identity{UID: os.Geteuid(), Home: t.TempDir()}
		target := filepath.Join(identity.Home, "real")
		if err := os.Mkdir(target, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(target, FileName), []byte(dcgsafe.DefaultConfig), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(identity.Home, DirName)); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(identity); err == nil {
			t.Fatal("Load accepted symlinked config directory")
		}
	})
}

func TestTrailingSlashRootIsNormalized(t *testing.T) {
	identity := account.Identity{UID: os.Geteuid(), Home: t.TempDir()}
	body := []byte("schema = 1\nallowed_roots = [\"" + identity.Home + "/capture/\"]\n")
	writeConfig(t, identity, body, 0o700, 0o600)
	policy, err := Load(identity)
	if err != nil {
		t.Fatal(err)
	}
	if len(policy.Roots) != 1 || policy.Roots[0] != filepath.Join(identity.Home, "capture") {
		t.Fatalf("normalized roots = %#v", policy.Roots)
	}
}

func writeConfig(t *testing.T, identity account.Identity, body []byte, dirMode, fileMode os.FileMode) {
	t.Helper()
	dir := filepath.Join(identity.Home, DirName)
	if err := os.Mkdir(dir, dirMode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, dirMode); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(Path(identity), body, fileMode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(Path(identity), fileMode); err != nil {
		t.Fatal(err)
	}
}

func assertMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("%s mode = %04o, want %04o", path, got, want)
	}
}

func setUmask(mask int) int {
	return umask(mask)
}

// The declaration is implemented in config_test_unix.go so this test remains
// explicit about its process-global umask manipulation.
var umask = func(mask int) int {
	panic(errors.New("umask implementation missing"))
}
