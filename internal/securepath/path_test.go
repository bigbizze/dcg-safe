package securepath

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"golang.org/x/sys/unix"
)

func TestReserveCreatesExactRegularCLOEXECFiles(t *testing.T) {
	root := trustedRoot(t, 0o775)
	paths := capturePaths(root, "evidence")
	oldMask := unix.Umask(0o777)
	reservation, err := Reserve([]string{root}, paths, os.Geteuid())
	unix.Umask(oldMask)
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range reservation.Files {
		ok, err := IsCLOEXEC(file.fd)
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			t.Fatalf("%s is not CLOEXEC", file.Path)
		}
		var stat unix.Stat_t
		if err := unix.Fstat(file.fd, &stat); err != nil {
			t.Fatal(err)
		}
		if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0o777 != 0o600 {
			t.Fatalf("%s mode/type = %#o", file.Path, stat.Mode)
		}
	}
	reservation.Rollback()
	for _, path := range paths {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s survived rollback: %v", path, err)
		}
	}
}

func TestCommitKeepsFilesAndTransfersDescriptors(t *testing.T) {
	root := trustedRoot(t, 0o755)
	paths := capturePaths(root, "kept")
	reservation, err := Reserve([]string{root}, paths, os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	reservation.Commit()
	for index, file := range reservation.Files {
		fd, err := file.TakeFD()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := unix.Write(fd, []byte{byte('0' + index)}); err != nil {
			t.Fatal(err)
		}
		if err := unix.Close(fd); err != nil {
			t.Fatal(err)
		}
		body, err := os.ReadFile(paths[index])
		if err != nil {
			t.Fatal(err)
		}
		if string(body) != string([]byte{byte('0' + index)}) {
			t.Fatalf("%s body = %q", paths[index], body)
		}
	}
}

func TestDestinationRejectionsDoNotCreateFiles(t *testing.T) {
	root := trustedRoot(t, 0o755)
	valid := capturePaths(root, "valid")
	tests := map[string][3]string{
		"relative": {
			"relative", valid[1], valid[2],
		},
		"outside": {
			filepath.Join(filepath.Dir(root), "outside.txt"), valid[1], valid[2],
		},
		"repeated separator": {
			root + "//out", valid[1], valid[2],
		},
		"traversal": {
			root + "/child/../out", valid[1], valid[2],
		},
		"trailing separator": {
			root + "/out/", valid[1], valid[2],
		},
		"duplicate": {
			valid[0], valid[0], valid[2],
		},
	}
	for name, paths := range tests {
		t.Run(name, func(t *testing.T) {
			if reservation, err := Reserve([]string{root}, paths, os.Geteuid()); err == nil {
				reservation.Rollback()
				t.Fatal("Reserve unexpectedly succeeded")
			}
			for _, path := range valid {
				if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("invalid setup created %s: %v", path, err)
				}
			}
		})
	}
}

func TestExistingFinalNamesAndSymlinksAreRejected(t *testing.T) {
	for _, kind := range []string{"file", "directory", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			root := trustedRoot(t, 0o755)
			paths := capturePaths(root, "capture")
			switch kind {
			case "file":
				if err := os.WriteFile(paths[1], []byte("existing"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err := os.Mkdir(paths[1], 0o700); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				target := filepath.Join(root, "target")
				if err := os.WriteFile(target, []byte("target"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, paths[1]); err != nil {
					t.Fatal(err)
				}
			}
			if reservation, err := Reserve([]string{root}, paths, os.Geteuid()); err == nil {
				reservation.Rollback()
				t.Fatal("Reserve unexpectedly replaced existing target")
			}
			if _, err := os.Lstat(paths[0]); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("ordinary failure did not roll back first file: %v", err)
			}
		})
	}
}

func TestSymlinkedRootAndParentAreRejected(t *testing.T) {
	t.Run("root", func(t *testing.T) {
		container := t.TempDir()
		realRoot := filepath.Join(container, "real")
		if err := os.Mkdir(realRoot, 0o755); err != nil {
			t.Fatal(err)
		}
		linkRoot := filepath.Join(container, "link")
		if err := os.Symlink(realRoot, linkRoot); err != nil {
			t.Fatal(err)
		}
		if reservation, err := Reserve([]string{linkRoot}, capturePaths(linkRoot, "x"), os.Geteuid()); err == nil {
			reservation.Rollback()
			t.Fatal("Reserve accepted symlinked root")
		}
	})
	t.Run("parent", func(t *testing.T) {
		root := trustedRoot(t, 0o755)
		realParent := filepath.Join(root, "real")
		if err := os.Mkdir(realParent, 0o755); err != nil {
			t.Fatal(err)
		}
		linkParent := filepath.Join(root, "link")
		if err := os.Symlink(realParent, linkParent); err != nil {
			t.Fatal(err)
		}
		paths := capturePaths(linkParent, "x")
		if reservation, err := Reserve([]string{root}, paths, os.Geteuid()); err == nil {
			reservation.Rollback()
			t.Fatal("Reserve accepted symlinked parent")
		}
	})
}

func TestDirectoryTrustRules(t *testing.T) {
	t.Run("group writable accepted", func(t *testing.T) {
		root := trustedRoot(t, 0o775)
		parent := filepath.Join(root, "group")
		if err := os.Mkdir(parent, 0o775); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(parent, 0o775); err != nil {
			t.Fatal(err)
		}
		reservation, err := Reserve([]string{root}, capturePaths(parent, "x"), os.Geteuid())
		if err != nil {
			t.Fatal(err)
		}
		reservation.Rollback()
	})
	t.Run("world writable root rejected", func(t *testing.T) {
		root := trustedRoot(t, 0o777)
		if reservation, err := Reserve([]string{root}, capturePaths(root, "x"), os.Geteuid()); err == nil {
			reservation.Rollback()
			t.Fatal("Reserve accepted world-writable root")
		}
	})
	t.Run("world writable parent rejected", func(t *testing.T) {
		root := trustedRoot(t, 0o755)
		parent := filepath.Join(root, "world")
		if err := os.Mkdir(parent, 0o777); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(parent, 0o777); err != nil {
			t.Fatal(err)
		}
		if reservation, err := Reserve([]string{root}, capturePaths(parent, "x"), os.Geteuid()); err == nil {
			reservation.Rollback()
			t.Fatal("Reserve accepted world-writable parent")
		}
	})
	t.Run("foreign owner rejected", func(t *testing.T) {
		root := trustedRoot(t, 0o755)
		if reservation, err := Reserve([]string{root}, capturePaths(root, "x"), os.Geteuid()+1); err == nil {
			reservation.Rollback()
			t.Fatal("Reserve accepted a root foreign to the supplied effective UID")
		}
	})
}

func TestPlatformTmpAliasAndUnrelatedMissingRoot(t *testing.T) {
	if err := CheckRoot("/tmp", os.Geteuid()); err != nil {
		t.Fatalf("/tmp alias unavailable: %v", err)
	}
	root, err := os.MkdirTemp("/tmp", "dcg-safe-test-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	paths := capturePaths(root, "tmp")
	reservation, err := Reserve([]string{"/definitely/missing/dcg-safe-root", "/tmp"}, paths, os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	reservation.Rollback()
}

func TestLongestMatchingRootSelection(t *testing.T) {
	root := filepath.Clean("/tmp/outer")
	deeper := filepath.Join(root, "nested")
	selected, err := selectRoot([]string{"/tmp", root, deeper}, filepath.Join(deeper, "out"))
	if err != nil {
		t.Fatal(err)
	}
	if selected != deeper {
		t.Fatalf("selected %q, want %q", selected, deeper)
	}
}

func TestConcurrentReservationHasOneWinner(t *testing.T) {
	root := trustedRoot(t, 0o755)
	paths := capturePaths(root, "same")
	start := make(chan struct{})
	type result struct {
		reservation *Reservation
		err         error
	}
	results := make(chan result, 2)
	var ready sync.WaitGroup
	ready.Add(2)
	for range 2 {
		go func() {
			ready.Done()
			<-start
			reservation, err := Reserve([]string{root}, paths, os.Geteuid())
			results <- result{reservation: reservation, err: err}
		}()
	}
	ready.Wait()
	close(start)
	first := <-results
	second := <-results
	winners := 0
	for _, item := range []result{first, second} {
		if item.err == nil {
			winners++
			item.reservation.Rollback()
		}
	}
	if winners != 1 {
		t.Fatalf("reservation winners = %d; errors: %v / %v", winners, first.err, second.err)
	}
}

func trustedRoot(t *testing.T, mode os.FileMode) string {
	t.Helper()
	root := t.TempDir()
	canonical, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	root = canonical
	if err := os.Chmod(root, mode); err != nil {
		t.Fatal(err)
	}
	return root
}

func capturePaths(root, prefix string) [3]string {
	return [3]string{
		filepath.Join(root, prefix+".stdout"),
		filepath.Join(root, prefix+".stderr"),
		filepath.Join(root, prefix+".status"),
	}
}
