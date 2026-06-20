//go:build !windows

package main

import "os/exec"

func setProcAttrs(cmd *exec.Cmd) {
	// No special process attributes on non-Windows
}
