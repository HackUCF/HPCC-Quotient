package checks

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

type Ping struct {
	Service
	Count           int
	AllowPacketLoss bool
	Percent         int
}

func (c Ping) Run(teamID uint, teamIdentifier string, target string, res chan Result) {
	// Set default count if not specified
	count := c.Count
	if count == 0 {
		count = 1
	}

	// Use configurable timeout from Service struct, with a minimum of 5 seconds
	timeout := c.Timeout
	if timeout == 0 {
		timeout = 30 // Default from config
	}
	if timeout < 5 {
		timeout = 5 // Minimum timeout for ping
	}

	// Use system ping command with configurable timeout and count
	cmd := exec.Command("timeout", strconv.Itoa(timeout), "ping", "-c", strconv.Itoa(count), "-W", "5", target)

	start := time.Now()
	output, err := cmd.Output()
	duration := time.Since(start)

	outputStr := string(output)
	fmt.Println(outputStr)
	fmt.Println(err)
	fmt.Println(duration)

	// Check if ping was successful by looking for "1 received" in the output
	// The timeout command may return non-zero exit code even when ping succeeds
	if err != nil && !strings.Contains(outputStr, "1 received") {
		res <- Result{
			Error: fmt.Sprintf("ping failed: %v", err),
			Debug: fmt.Sprintf("Target: %s, Count: %d, Timeout: %ds, Duration: %v, Output: %s", target, count, timeout, duration, outputStr),
		}
		return
	}

	res <- Result{
		Status: true,
		Points: c.Points,
		Debug:  fmt.Sprintf("Target: %s, Count: %d, Duration: %v", target, count, duration),
	}
}

func (c Ping) GetService() Service {
	return c.Service
}
