//go:build !windows

package tokens

import "errors"

func profileHomes() ([]string, error) {
	return nil, errors.New("profile enumeration is windows-only")
}
