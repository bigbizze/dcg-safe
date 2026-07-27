package account

import (
	"os"
	"os/user"
	"strconv"
	"testing"
)

func TestEffectiveIgnoresHOME(t *testing.T) {
	t.Setenv("HOME", filepathForPoisonedHome(t))
	got, err := Effective()
	if err != nil {
		t.Fatal(err)
	}
	entry, err := user.LookupId(strconv.Itoa(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	if got.UID != os.Geteuid() {
		t.Fatalf("UID = %d, want %d", got.UID, os.Geteuid())
	}
	if got.Home != entry.HomeDir {
		t.Fatalf("home = %q, want account home %q", got.Home, entry.HomeDir)
	}
	if got.Home == os.Getenv("HOME") {
		t.Fatalf("effective home unexpectedly came from HOME=%q", os.Getenv("HOME"))
	}
}

func filepathForPoisonedHome(t *testing.T) string {
	t.Helper()
	return t.TempDir() + "/poisoned"
}
