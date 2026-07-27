// Package account resolves identity information from the effective UID.
package account

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
)

// Identity is the effective operating-system account used for policy checks.
type Identity struct {
	UID  int
	Home string
}

// Effective resolves the effective UID through the system account database.
// It deliberately does not consult HOME.
func Effective() (Identity, error) {
	uid := os.Geteuid()
	entry, err := user.LookupId(strconv.Itoa(uid))
	if err != nil {
		return Identity{}, fmt.Errorf("look up effective UID %d: %w", uid, err)
	}
	if entry.HomeDir == "" {
		return Identity{}, fmt.Errorf("effective UID %d has no account home", uid)
	}
	return Identity{UID: uid, Home: entry.HomeDir}, nil
}
