// Package capture executes one child command with securely-reserved evidence
// files.
package capture

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/bigbizze/dcg-safe/internal/securepath"
	"golang.org/x/sys/unix"
)

const (
	SetupFailure      = 125
	NotInvokable      = 126
	CommandNotFound   = 127
	signalOutcomeBase = 128
)

// Options describes one capture invocation.
type Options struct {
	StdoutPath string
	StderrPath string
	StatusPath string
	Command    []string
	Roots      []string
	UID        int
	Stdin      io.Reader
}

type runtimeOps struct {
	closeOutput func(*os.File) error
	status      statusOps
}

type statusOps struct {
	write    func(int, []byte) (int, error)
	truncate func(int, int64) error
	seek     func(int, int64, int) (int64, error)
	close    func(int) error
	dup      func(int) (int, error)
	fstat    func(int, *unix.Stat_t) error
}

func defaultRuntimeOps() runtimeOps {
	return runtimeOps{
		closeOutput: func(file *os.File) error { return file.Close() },
		status: statusOps{
			write:    unix.Write,
			truncate: unix.Ftruncate,
			seek:     unix.Seek,
			close:    unix.Close,
			dup:      unix.Dup,
			fstat:    unix.Fstat,
		},
	}
}

// Execute reserves all evidence files, invokes the command directly, and
// returns the wrapper outcome.
func Execute(options Options, diagnostics io.Writer) int {
	return execute(options, diagnostics, defaultRuntimeOps())
}

func execute(options Options, diagnostics io.Writer, ops runtimeOps) int {
	if diagnostics == nil {
		diagnostics = io.Discard
	}
	if len(options.Command) == 0 || options.Command[0] == "" {
		fmt.Fprintln(diagnostics, "dcg-safe: capture requires a command after --")
		return SetupFailure
	}
	if options.Stdin == nil {
		options.Stdin = os.Stdin
	}

	reservation, err := securepath.Reserve(
		options.Roots,
		[3]string{options.StdoutPath, options.StderrPath, options.StatusPath},
		options.UID,
	)
	if err != nil {
		fmt.Fprintln(diagnostics, "dcg-safe: setup:", err)
		return SetupFailure
	}

	var takenFDs []int
	take := func(index int) (int, error) {
		fd, takeErr := reservation.Files[index].TakeFD()
		if takeErr == nil {
			takenFDs = append(takenFDs, fd)
		}
		return fd, takeErr
	}
	stdoutFD, err := take(0)
	if err != nil {
		closeFDs(takenFDs)
		reservation.Rollback()
		fmt.Fprintln(diagnostics, "dcg-safe: setup stdout:", err)
		return SetupFailure
	}
	stderrFD, err := take(1)
	if err != nil {
		closeFDs(takenFDs)
		reservation.Rollback()
		fmt.Fprintln(diagnostics, "dcg-safe: setup stderr:", err)
		return SetupFailure
	}
	statusFD, err := take(2)
	if err != nil {
		closeFDs(takenFDs)
		reservation.Rollback()
		fmt.Fprintln(diagnostics, "dcg-safe: setup status:", err)
		return SetupFailure
	}

	stdoutFile, err := securepath.NewOSFile(stdoutFD, options.StdoutPath)
	if err != nil {
		closeFDs([]int{stderrFD, statusFD})
		reservation.Rollback()
		fmt.Fprintln(diagnostics, "dcg-safe: setup stdout:", err)
		return SetupFailure
	}
	stderrFile, err := securepath.NewOSFile(stderrFD, options.StderrPath)
	if err != nil {
		_ = stdoutFile.Close()
		closeFDs([]int{statusFD})
		reservation.Rollback()
		fmt.Fprintln(diagnostics, "dcg-safe: setup stderr:", err)
		return SetupFailure
	}
	reservation.Commit()

	command := exec.Command(options.Command[0], options.Command[1:]...)
	command.Stdin = options.Stdin
	command.Stdout = stdoutFile
	command.Stderr = stderrFile

	signalChannel := make(chan os.Signal, 8)
	signal.Notify(
		signalChannel,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGHUP,
		syscall.SIGQUIT,
	)
	startErr := command.Start()
	if startErr != nil {
		signal.Stop(signalChannel)
		outcome := invocationOutcome(startErr)
		fmt.Fprintf(diagnostics, "dcg-safe: invoke %q: %v\n", options.Command[0], startErr)
		if err := finishFiles(stdoutFile, stderrFile, statusFD, outcome, ops); err != nil {
			fmt.Fprintln(diagnostics, "dcg-safe: finalize:", err)
			return SetupFailure
		}
		return outcome
	}

	forwardDone := make(chan struct{})
	go func() {
		for {
			select {
			case received := <-signalChannel:
				if received != nil {
					_ = command.Process.Signal(received)
				}
			case <-forwardDone:
				return
			}
		}
	}()

	waitErr := command.Wait()
	close(forwardDone)
	signal.Stop(signalChannel)

	outcome, outcomeErr := completedOutcome(command.ProcessState, waitErr)
	if outcomeErr != nil {
		fmt.Fprintln(diagnostics, "dcg-safe: wait:", outcomeErr)
	}
	if err := finishFiles(stdoutFile, stderrFile, statusFD, outcome, ops); err != nil {
		fmt.Fprintln(diagnostics, "dcg-safe: finalize:", err)
		return SetupFailure
	}
	return outcome
}

func finishFiles(stdout, stderr *os.File, statusFD, outcome int, ops runtimeOps) error {
	var closeErrors []error
	if err := ops.closeOutput(stdout); err != nil {
		closeErrors = append(closeErrors, fmt.Errorf("close stdout: %w", err))
	}
	if err := ops.closeOutput(stderr); err != nil {
		closeErrors = append(closeErrors, fmt.Errorf("close stderr: %w", err))
	}
	closeErr := errors.Join(closeErrors...)
	if err := finalizeStatus(statusFD, outcome, closeErr, ops.status); err != nil {
		return err
	}
	return closeErr
}

func finalizeStatus(fd, outcome int, priorError error, ops statusOps) error {
	backupFD := -1
	if duplicate, err := ops.dup(fd); err == nil {
		backupFD = duplicate
		unix.CloseOnExec(backupFD)
	}
	truncateIncomplete := func() {
		if backupFD >= 0 {
			_ = ops.truncate(backupFD, 0)
			return
		}
		_ = ops.truncate(fd, 0)
	}
	closeAll := func() {
		_ = ops.close(fd)
		if backupFD >= 0 {
			_ = ops.close(backupFD)
		}
	}
	if priorError != nil {
		truncateIncomplete()
		closeAll()
		return priorError
	}
	if err := ops.truncate(fd, 0); err != nil {
		truncateIncomplete()
		closeAll()
		return fmt.Errorf("truncate status: %w", err)
	}
	if _, err := ops.seek(fd, 0, io.SeekStart); err != nil {
		truncateIncomplete()
		closeAll()
		return fmt.Errorf("seek status: %w", err)
	}
	body := []byte(strconv.Itoa(outcome) + "\n")
	remaining := body
	for len(remaining) > 0 {
		n, err := ops.write(fd, remaining)
		if err != nil {
			truncateIncomplete()
			closeAll()
			return fmt.Errorf("write status: %w", err)
		}
		if n <= 0 || n > len(remaining) {
			truncateIncomplete()
			closeAll()
			return io.ErrShortWrite
		}
		remaining = remaining[n:]
	}
	var stat unix.Stat_t
	if err := ops.fstat(fd, &stat); err != nil {
		truncateIncomplete()
		closeAll()
		return fmt.Errorf("verify status: %w", err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Size != int64(len(body)) {
		truncateIncomplete()
		closeAll()
		return errors.New("status did not finalize as an exact regular-file record")
	}
	if err := ops.close(fd); err != nil {
		if backupFD >= 0 {
			_ = ops.truncate(backupFD, 0)
			_ = ops.close(backupFD)
		}
		return fmt.Errorf("close status: %w", err)
	}
	if backupFD >= 0 {
		_ = ops.close(backupFD)
	}
	return nil
}

func invocationOutcome(err error) int {
	switch {
	case errors.Is(err, exec.ErrDot):
		return NotInvokable
	case errors.Is(err, exec.ErrNotFound), errors.Is(err, os.ErrNotExist), errors.Is(err, unix.ENOENT):
		return CommandNotFound
	case errors.Is(err, os.ErrPermission),
		errors.Is(err, unix.EACCES),
		errors.Is(err, unix.ENOEXEC),
		errors.Is(err, unix.EISDIR),
		errors.Is(err, unix.ENOTDIR),
		errors.Is(err, unix.ELOOP),
		errors.Is(err, unix.ENAMETOOLONG),
		errors.Is(err, unix.ETXTBSY),
		errors.Is(err, unix.EPERM):
		return NotInvokable
	default:
		return SetupFailure
	}
}

func completedOutcome(state *os.ProcessState, waitErr error) (int, error) {
	if state == nil {
		if waitErr == nil {
			waitErr = errors.New("child returned no process state")
		}
		return SetupFailure, waitErr
	}
	waitStatus, ok := state.Sys().(syscall.WaitStatus)
	if ok {
		if waitStatus.Signaled() {
			return signalOutcomeBase + int(waitStatus.Signal()), nil
		}
		if waitStatus.Exited() {
			return waitStatus.ExitStatus(), nil
		}
	}
	if exitCode := state.ExitCode(); exitCode >= 0 {
		return exitCode, nil
	}
	if waitErr == nil {
		waitErr = errors.New("child outcome is unavailable")
	}
	return SetupFailure, waitErr
}

func closeFDs(fds []int) {
	for _, fd := range fds {
		if fd >= 0 {
			_ = unix.Close(fd)
		}
	}
}
