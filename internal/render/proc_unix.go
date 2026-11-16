//go:build !windows

package render

import (
	"os/exec"
	"syscall"
)

// isolate puts the browser in its own process group so the whole tree
// (renderer, GPU and utility processes) can be stopped together.
func isolate(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

func killTree(cmd *exec.Cmd) {
	if cmd.Process == nil {
		return
	}
	if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); err != nil {
		cmd.Process.Kill()
	}
}
