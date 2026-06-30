// Package platform contains OS-specific operations (timestamps, ACLs, command
// execution, OS detection, VSS). Cross-platform stubs allow the project to
// build and unit-test on non-Windows hosts while the real logic lives behind
// //go:build windows files.
package platform

import (
	"bytes"
	"context"
	"os/exec"
	"strings"
	"time"
)

// CmdResult holds the outcome of an external command invocation.
type CmdResult struct {
	Cmd      string
	Args     []string
	Stdout   string
	Stderr   string
	ExitCode int
	Err      error
	Duration time.Duration
}

// Combined returns stdout, falling back to stderr if stdout is empty.
func (r CmdResult) Combined() string {
	if strings.TrimSpace(r.Stdout) != "" {
		return r.Stdout
	}
	return r.Stderr
}

// RunContext executes a command read-only (collection tools never mutate the
// system) with a timeout and captures stdout/stderr.
func RunContext(ctx context.Context, timeout time.Duration, name string, args ...string) CmdResult {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	start := time.Now()
	cmd := exec.CommandContext(cctx, name, args...)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err := cmd.Run()
	res := CmdResult{
		Cmd:      name,
		Args:     args,
		Stdout:   out.String(),
		Stderr:   errb.String(),
		Err:      err,
		Duration: time.Since(start),
	}
	if cmd.ProcessState != nil {
		res.ExitCode = cmd.ProcessState.ExitCode()
	}
	return res
}

// PowerShell runs a PowerShell command non-interactively. Used widely for
// structured data collection (CIM/WMI, network, services) where parsing native
// APIs would be prohibitively complex.
func PowerShell(ctx context.Context, timeout time.Duration, script string) CmdResult {
	return RunContext(ctx, timeout, "powershell.exe",
		"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
		"-Command", script)
}
