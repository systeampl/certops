package main

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

const fleetSSHTimeout = 30 * time.Second

func fleetSSHArgs(host fleetHost, remote string) []string {
	userHost := host.Address
	if strings.TrimSpace(host.User) != "" {
		userHost = host.User + "@" + host.Address
	}
	args := []string{
		"-o", "BatchMode=yes",
		"-o", "StrictHostKeyChecking=accept-new",
		"-o", "ConnectTimeout=10",
		"-o", "ConnectionAttempts=1",
		"-o", "ServerAliveInterval=10",
		"-o", "ServerAliveCountMax=2",
	}
	if strings.TrimSpace(host.Port) != "" {
		args = append(args, "-p", host.Port)
	}
	if strings.TrimSpace(host.IdentityFile) != "" {
		args = append(args, "-i", host.IdentityFile)
	}
	args = append(args, userHost, remote)
	return args
}

func fleetSSH(host fleetHost, remote string, stdin []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), fleetSSHTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "ssh", fleetSSHArgs(host, remote)...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		if ctx.Err() != nil {
			return out, fmt.Errorf("SSH command timed out after %s: %w", fleetSSHTimeout, ctx.Err())
		}
		return out, fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return out, nil
}
