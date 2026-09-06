//go:build linux

package proxy

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

type linuxTcShaper struct{}

func newPlatformTcShaper() TcShaper {
	return &linuxTcShaper{}
}

func (s *linuxTcShaper) LimitPort(ctx context.Context, iface string, port int, rateKbps int) error {
	if err := CheckPortRange(port); err != nil {
		return err
	}

	// 1. Ensure root HTB qdisc exists on device. Ignore error if it already exists.
	// Command: tc qdisc add dev <iface> root handle 1: htb default 10
	_ = exec.CommandContext(ctx, "tc", "qdisc", "add", "dev", iface, "root", "handle", "1:", "htb", "default", "10").Run()

	// 2. Add class. Ignore error if already exists, but delete first if we are updating.
	classID := fmt.Sprintf("1:%d", port)
	rateStr := fmt.Sprintf("%dkbit", rateKbps)
	_ = exec.CommandContext(ctx, "tc", "class", "del", "dev", iface, "classid", classID).Run()

	cmdClass := exec.CommandContext(ctx, "tc", "class", "add", "dev", iface, "parent", "1:", "classid", classID, "htb", "rate", rateStr, "ceil", rateStr)
	if out, err := cmdClass.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to create tc class: %w (%s)", err, strings.TrimSpace(string(out)))
	}

	// 3. Add filters for source port and destination port. Delete first to prevent duplicates.
	// Destination port filter:
	_ = exec.CommandContext(ctx, "tc", "filter", "del", "dev", iface, "parent", "1:", "protocol", "ip", "prio", "1", "u32", "match", "ip", "dport", fmt.Sprintf("%d", port), "0xffff").Run()
	cmdFilterDst := exec.CommandContext(ctx, "tc", "filter", "add", "dev", iface, "parent", "1:", "protocol", "ip", "prio", "1", "u32", "match", "ip", "dport", fmt.Sprintf("%d", port), "0xffff", "flowid", classID)
	if out, err := cmdFilterDst.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to create tc dport filter: %w (%s)", err, strings.TrimSpace(string(out)))
	}

	// Source port filter:
	_ = exec.CommandContext(ctx, "tc", "filter", "del", "dev", iface, "parent", "1:", "protocol", "ip", "prio", "1", "u32", "match", "ip", "sport", fmt.Sprintf("%d", port), "0xffff").Run()
	cmdFilterSrc := exec.CommandContext(ctx, "tc", "filter", "add", "dev", iface, "parent", "1:", "protocol", "ip", "prio", "1", "u32", "match", "ip", "sport", fmt.Sprintf("%d", port), "0xffff", "flowid", classID)
	if out, err := cmdFilterSrc.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to create tc sport filter: %w (%s)", err, strings.TrimSpace(string(out)))
	}

	return nil
}

func (s *linuxTcShaper) ClearPortLimits(ctx context.Context, iface string, port int) error {
	if err := CheckPortRange(port); err != nil {
		return err
	}

	classID := fmt.Sprintf("1:%d", port)

	// Delete filters
	_ = exec.CommandContext(ctx, "tc", "filter", "del", "dev", iface, "parent", "1:", "protocol", "ip", "prio", "1", "u32", "match", "ip", "dport", fmt.Sprintf("%d", port), "0xffff").Run()
	_ = exec.CommandContext(ctx, "tc", "filter", "del", "dev", iface, "parent", "1:", "protocol", "ip", "prio", "1", "u32", "match", "ip", "sport", fmt.Sprintf("%d", port), "0xffff").Run()

	// Delete class
	cmdDelClass := exec.CommandContext(ctx, "tc", "class", "del", "dev", iface, "classid", classID)
	if out, err := cmdDelClass.CombinedOutput(); err != nil {
		// Ignore error if class doesn't exist
		if !strings.Contains(string(out), "Cannot find") && !strings.Contains(string(out), "No such file") {
			return fmt.Errorf("failed to delete tc class: %w (%s)", err, strings.TrimSpace(string(out)))
		}
	}

	return nil
}

func (s *linuxTcShaper) ClearAll(ctx context.Context, iface string) error {
	// Delete the root qdisc to clear all classes and filters
	cmd := exec.CommandContext(ctx, "tc", "qdisc", "del", "dev", iface, "root")
	if out, err := cmd.CombinedOutput(); err != nil {
		if !strings.Contains(string(out), "Invalid argument") && !strings.Contains(string(out), "No such file") {
			return fmt.Errorf("failed to clear tc root: %w (%s)", err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}
