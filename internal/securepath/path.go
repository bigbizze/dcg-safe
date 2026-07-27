// Package securepath reserves new capture files beneath trusted roots using
// descriptor-relative traversal.
package securepath

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

const captureMode = 0o600

// Reservation contains stdout, stderr, and status files in that order.
// Call Commit before starting the child, or Rollback on setup failure.
type Reservation struct {
	Files     [3]*File
	committed bool
}

// File is one securely-created capture file.
type File struct {
	Path     string
	fd       int
	parentFD int
	base     string
}

type prepared struct {
	path     string
	parentFD int
	base     string
}

// Reserve validates all destinations, opens their parent directories without
// following symlinks, and atomically reserves all three final names.
func Reserve(roots []string, destinations [3]string, uid int) (*Reservation, error) {
	if len(roots) == 0 {
		return nil, errors.New("policy has no allowed roots")
	}
	seen := make(map[string]struct{}, len(destinations))
	selected := make([]string, len(destinations))
	for index, destination := range destinations {
		if err := validateDestination(destination); err != nil {
			return nil, fmt.Errorf("destination %d: %w", index+1, err)
		}
		if _, ok := seen[destination]; ok {
			return nil, fmt.Errorf("destination %d duplicates another capture path", index+1)
		}
		seen[destination] = struct{}{}
		root, err := selectRoot(roots, destination)
		if err != nil {
			return nil, fmt.Errorf("destination %d: %w", index+1, err)
		}
		if destination == root {
			return nil, fmt.Errorf("destination %d names the configured root, not a file below it", index+1)
		}
		selected[index] = root
	}

	preparedPaths := make([]prepared, 0, len(destinations))
	closePrepared := func() {
		for _, item := range preparedPaths {
			if item.parentFD >= 0 {
				_ = unix.Close(item.parentFD)
			}
		}
	}
	for index, destination := range destinations {
		item, err := prepare(selected[index], destination, uid)
		if err != nil {
			closePrepared()
			return nil, fmt.Errorf("prepare %s: %w", destination, err)
		}
		preparedPaths = append(preparedPaths, item)
	}

	reservation := &Reservation{}
	for index, item := range preparedPaths {
		fd, err := createFinal(item.parentFD, item.base, uid)
		if err != nil {
			reservation.Rollback()
			for remaining := index; remaining < len(preparedPaths); remaining++ {
				_ = unix.Close(preparedPaths[remaining].parentFD)
			}
			return nil, fmt.Errorf("reserve %s: %w", item.path, err)
		}
		reservation.Files[index] = &File{
			Path:     item.path,
			fd:       fd,
			parentFD: item.parentFD,
			base:     item.base,
		}
	}
	return reservation, nil
}

// Commit ends the rollback phase and closes retained parent descriptors. The
// three capture file descriptors remain open and CLOEXEC.
func (reservation *Reservation) Commit() {
	if reservation == nil || reservation.committed {
		return
	}
	for _, file := range reservation.Files {
		if file != nil && file.parentFD >= 0 {
			_ = unix.Close(file.parentFD)
			file.parentFD = -1
		}
	}
	reservation.committed = true
}

// Rollback closes and unlinks every successfully-created file using unlinkat.
// It is safe to call more than once.
func (reservation *Reservation) Rollback() {
	if reservation == nil || reservation.committed {
		return
	}
	for index := len(reservation.Files) - 1; index >= 0; index-- {
		file := reservation.Files[index]
		if file == nil {
			continue
		}
		if file.fd >= 0 {
			_ = unix.Close(file.fd)
			file.fd = -1
		}
		if file.parentFD >= 0 {
			_ = unix.Unlinkat(file.parentFD, file.base, 0)
			_ = unix.Close(file.parentFD)
			file.parentFD = -1
		}
	}
}

// TakeFD transfers ownership of the capture descriptor to the caller.
func (file *File) TakeFD() (int, error) {
	if file == nil || file.fd < 0 {
		return -1, errors.New("capture descriptor is unavailable")
	}
	fd := file.fd
	file.fd = -1
	return fd, nil
}

// CheckRoot validates one configured root without considering any unrelated
// roots.
func CheckRoot(root string, uid int) error {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return errors.New("root is not a normalized absolute path")
	}
	fd, err := openRoot(root, uid)
	if err != nil {
		return err
	}
	return unix.Close(fd)
}

func validateDestination(path string) error {
	if path == "" {
		return errors.New("path must not be empty")
	}
	if strings.IndexByte(path, 0) >= 0 {
		return errors.New("path contains NUL")
	}
	if !filepath.IsAbs(path) {
		return errors.New("path must be absolute")
	}
	if strings.Contains(path, string(filepath.Separator)+string(filepath.Separator)) {
		return errors.New("repeated path separators are not allowed")
	}
	for _, component := range strings.Split(path, string(filepath.Separator)) {
		if component == "." || component == ".." {
			return errors.New("traversal components are not allowed")
		}
	}
	if filepath.Clean(path) != path {
		return errors.New("path must already be normalized")
	}
	if filepath.Base(path) == string(filepath.Separator) || filepath.Base(path) == "." {
		return errors.New("path must name a file")
	}
	return nil
}

func selectRoot(roots []string, destination string) (string, error) {
	selected := ""
	for _, root := range roots {
		if !filepath.IsAbs(root) || filepath.Clean(root) != root {
			return "", fmt.Errorf("configured root %q is not normalized and absolute", root)
		}
		if pathWithin(destination, root) && len(root) > len(selected) {
			selected = root
		}
	}
	if selected == "" {
		return "", errors.New("path is outside configured roots")
	}
	return selected, nil
}

func pathWithin(path, root string) bool {
	if path == root {
		return true
	}
	if root == string(filepath.Separator) {
		return strings.HasPrefix(path, root)
	}
	return strings.HasPrefix(path, root+string(filepath.Separator))
}

func prepare(root, destination string, uid int) (prepared, error) {
	rootFD, err := openRoot(root, uid)
	if err != nil {
		return prepared{}, err
	}
	relative := strings.TrimPrefix(destination, root)
	relative = strings.TrimPrefix(relative, string(filepath.Separator))
	components := strings.Split(relative, string(filepath.Separator))
	if len(components) == 0 || components[len(components)-1] == "" {
		_ = unix.Close(rootFD)
		return prepared{}, errors.New("destination has no final file name")
	}

	currentFD := rootFD
	for _, component := range components[:len(components)-1] {
		nextFD, err := unix.Openat(
			currentFD,
			component,
			unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
			0,
		)
		if err != nil {
			_ = unix.Close(currentFD)
			return prepared{}, fmt.Errorf("open parent %q without following symlinks: %w", component, err)
		}
		_ = unix.Close(currentFD)
		currentFD = nextFD
		if err := validateOwnedDirectory(currentFD, uid); err != nil {
			_ = unix.Close(currentFD)
			return prepared{}, fmt.Errorf("parent %q: %w", component, err)
		}
	}
	return prepared{
		path:     destination,
		parentFD: currentFD,
		base:     components[len(components)-1],
	}, nil
}

func openRoot(root string, uid int) (int, error) {
	if root == "/tmp" {
		canonical, err := filepath.EvalSymlinks(root)
		if err != nil {
			return -1, fmt.Errorf("resolve platform /tmp alias: %w", err)
		}
		canonical = filepath.Clean(canonical)
		fd, err := openAbsoluteNoSymlinks(canonical)
		if err != nil {
			return -1, fmt.Errorf("open platform /tmp target: %w", err)
		}
		var stat unix.Stat_t
		if err := unix.Fstat(fd, &stat); err != nil {
			_ = unix.Close(fd)
			return -1, fmt.Errorf("stat platform /tmp target: %w", err)
		}
		if stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Uid != 0 || stat.Mode&unix.S_ISVTX == 0 {
			_ = unix.Close(fd)
			return -1, errors.New("platform /tmp target must be a root-owned sticky directory")
		}
		return fd, nil
	}

	fd, err := openAbsoluteNoSymlinks(root)
	if err != nil {
		return -1, fmt.Errorf("open configured root without following symlinks: %w", err)
	}
	if err := validateOwnedDirectory(fd, uid); err != nil {
		_ = unix.Close(fd)
		return -1, fmt.Errorf("configured root: %w", err)
	}
	return fd, nil
}

func openAbsoluteNoSymlinks(path string) (int, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return -1, errors.New("path is not normalized and absolute")
	}
	currentFD, err := unix.Open(
		string(filepath.Separator),
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return -1, err
	}
	if path == string(filepath.Separator) {
		return currentFD, nil
	}
	components := strings.Split(strings.TrimPrefix(path, string(filepath.Separator)), string(filepath.Separator))
	for _, component := range components {
		nextFD, err := unix.Openat(
			currentFD,
			component,
			unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
			0,
		)
		_ = unix.Close(currentFD)
		if err != nil {
			return -1, err
		}
		currentFD = nextFD
	}
	return currentFD, nil
}

func validateOwnedDirectory(fd, uid int) error {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR {
		return errors.New("must be a directory")
	}
	if int(stat.Uid) != uid {
		return fmt.Errorf("must be owned by effective UID %d", uid)
	}
	if stat.Mode&0o002 != 0 {
		return errors.New("must not be world-writable")
	}
	return nil
}

func createFinal(parentFD int, base string, uid int) (int, error) {
	fd, err := unix.Openat(
		parentFD,
		base,
		unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		captureMode,
	)
	if err != nil {
		return -1, err
	}
	cleanup := func(cause error) (int, error) {
		_ = unix.Close(fd)
		_ = unix.Unlinkat(parentFD, base, 0)
		return -1, cause
	}
	if err := unix.Fchmod(fd, captureMode); err != nil {
		return cleanup(fmt.Errorf("set mode: %w", err))
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return cleanup(fmt.Errorf("verify file: %w", err))
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return cleanup(errors.New("created target is not a regular file"))
	}
	if int(stat.Uid) != uid {
		return cleanup(fmt.Errorf("created target is not owned by effective UID %d", uid))
	}
	if stat.Mode&0o777 != captureMode {
		return cleanup(fmt.Errorf("created target mode is %04o, want %04o", stat.Mode&0o777, captureMode))
	}
	return fd, nil
}

// IsCLOEXEC reports whether fd has close-on-exec set. It is exported for
// focused security tests.
func IsCLOEXEC(fd int) (bool, error) {
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
	if err != nil {
		return false, err
	}
	return flags&unix.FD_CLOEXEC != 0, nil
}

// NewOSFile converts a transferred descriptor into an os.File.
func NewOSFile(fd int, name string) (*os.File, error) {
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		_ = unix.Close(fd)
		return nil, errors.New("invalid file descriptor")
	}
	return file, nil
}
