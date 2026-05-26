// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package connection

import (
	"regexp"
	"strings"
	"time"
)

// DeviceMetadata contains stable identity fields discovered from a Cisco
// device. Empty fields mean the value was not available in command output.
type DeviceMetadata struct {
	HostName   string
	HostID     string
	HostType   string
	OSType     string
	OSVersion  string
	Model      string
	Serial     string
	Uptime     time.Duration
	DetectedAt time.Time
}

func (m DeviceMetadata) UptimeSeconds(now time.Time) int64 {
	if m.Uptime <= 0 {
		return 0
	}
	if m.DetectedAt.IsZero() || now.Before(m.DetectedAt) {
		return int64(m.Uptime.Seconds())
	}
	return int64((m.Uptime + now.Sub(m.DetectedAt)).Seconds())
}

func parseDeviceMetadataFromShowVersion(output string, detectedAt time.Time) DeviceMetadata {
	metadata := DeviceMetadata{
		OSType:     detectOSTypeFromShowVersion(output),
		DetectedAt: detectedAt,
	}

	metadata.OSVersion = firstNonEmpty(
		firstSubmatch(output, `(?im)\bCisco IOS XE Software,\s+Version\s+([^\r\n,]+)`),
		firstSubmatch(output, `(?im)\bCisco IOS Software,[^\r\n]*,\s+Version\s+([^\r\n,]+)`),
		firstSubmatch(output, `(?im)\bNXOS:\s+version\s+([^\r\n\[]+)`),
		firstSubmatch(output, `(?im)\bNX-OS.*?Version\s+([^\r\n,]+)`),
		firstSubmatch(output, `(?im)\bSystem version:\s+([^\r\n]+)`),
	)
	metadata.HostName = firstNonEmpty(
		firstSubmatch(output, `(?im)^\s*Device name:\s*(\S+)`),
		firstSubmatch(output, `(?im)^\s*Kernel uptime is\s+(\S+)`),
		firstSubmatch(output, `(?im)^(\S+)\s+uptime is\s+`),
	)
	metadata.Model = firstNonEmpty(
		firstSubmatch(output, `(?im)^\s*cisco\s+(\S+)\s+\([^)]+\)\s+processor`),
		firstSubmatch(output, `(?im)^\s*cisco\s+(Nexus[^\r\n]+?)\s+Chassis`),
		firstSubmatch(output, `(?im)^\s*Model number\s*:\s*(\S+)`),
		firstSubmatch(output, `(?im)^\s*Model\s*:\s*(\S+)`),
		firstSubmatch(output, `(?im)^\s*Chassis\s*:\s*(\S+)`),
	)
	metadata.Serial = firstNonEmpty(
		firstSubmatch(output, `(?im)^\s*Processor board ID\s+(\S+)`),
		firstSubmatch(output, `(?im)^\s*System serial number\s*:\s*(\S+)`),
		firstSubmatch(output, `(?im)^\s*Chassis Serial Number\s*:\s*(\S+)`),
	)
	metadata.Uptime = parseCiscoUptime(output)

	metadata.Model = cleanMetadataValue(metadata.Model)
	metadata.HostType = metadata.Model
	metadata.HostID = metadata.Serial
	metadata.OSVersion = cleanMetadataValue(metadata.OSVersion)
	return metadata
}

func parseCiscoUptime(output string) time.Duration {
	for _, pattern := range []string{
		`(?im)^\S+\s+uptime is\s+(.+)$`,
		`(?im)^\s*Kernel uptime is\s+(.+)$`,
	} {
		if raw := firstSubmatch(output, pattern); raw != "" {
			return parseCiscoUptimeDuration(raw)
		}
	}
	return 0
}

func parseCiscoUptimeDuration(raw string) time.Duration {
	raw = strings.TrimSpace(strings.TrimSuffix(raw, "."))
	raw = strings.ReplaceAll(raw, "(s)", "s")
	if raw == "" {
		return 0
	}

	re := regexp.MustCompile(`(?i)(\d+)\s*(years?|weeks?|days?|hours?|hrs?|minutes?|mins?|seconds?|secs?)`)
	matches := re.FindAllStringSubmatch(raw, -1)
	var total time.Duration
	for _, match := range matches {
		if len(match) != 3 {
			continue
		}
		value := strToInt64(match[1])
		switch strings.ToLower(match[2]) {
		case "year", "years":
			total += time.Duration(value) * 365 * 24 * time.Hour
		case "week", "weeks":
			total += time.Duration(value) * 7 * 24 * time.Hour
		case "day", "days":
			total += time.Duration(value) * 24 * time.Hour
		case "hour", "hours", "hr", "hrs":
			total += time.Duration(value) * time.Hour
		case "minute", "minutes", "min", "mins":
			total += time.Duration(value) * time.Minute
		case "second", "seconds", "sec", "secs":
			total += time.Duration(value) * time.Second
		}
	}
	return total
}

func firstSubmatch(value, pattern string) string {
	re := regexp.MustCompile(pattern)
	matches := re.FindStringSubmatch(value)
	if len(matches) < 2 {
		return ""
	}
	return strings.TrimSpace(matches[1])
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	return ""
}

func cleanMetadataValue(value string) string {
	value = strings.TrimSpace(value)
	value = strings.Trim(value, ",")
	return strings.Join(strings.Fields(value), " ")
}

func strToInt64(value string) int64 {
	var parsed int64
	for _, char := range value {
		if char < '0' || char > '9' {
			return parsed
		}
		parsed = parsed*10 + int64(char-'0')
	}
	return parsed
}
