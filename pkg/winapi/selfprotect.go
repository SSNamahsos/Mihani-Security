package winapi

import (
	"errors"
	"os/exec"
	"strings"
)

func HardenDataDir(dir string) error {
	cmd := exec.Command("icacls", dir, "/inheritance:r",
		"/grant:r", "SYSTEM:(OI)(CI)F",
		"/grant:r", "Administrators:(OI)(CI)F",
		"/grant:r", "Users:(OI)(CI)RX",
		"/remove:g", "Everyone",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return errors.New(strings.TrimSpace(string(out)) + ": " + err.Error())
	}
	return nil
}

const protectedServiceSDDL = "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)"

func HardenServiceACL(serviceName string) error {
	cmd := exec.Command("sc", "sdset", serviceName, protectedServiceSDDL)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return errors.New(strings.TrimSpace(string(out)) + ": " + err.Error())
	}
	return nil
}
