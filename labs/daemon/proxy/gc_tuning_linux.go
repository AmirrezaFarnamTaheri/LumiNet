//go:build linux

package proxy

import (
	"bufio"
	"os"
	"strconv"
	"strings"
)

func getSystemTotalMemory() uint64 {
	file, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "MemTotal:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				val, err := strconv.ParseUint(fields[1], 10, 64)
				if err == nil {
					return val * 1024 // /proc/meminfo is in kB
				}
			}
		}
	}
	return 0
}
