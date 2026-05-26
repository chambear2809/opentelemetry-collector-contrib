// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package connection

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestClient_DetectOSType(t *testing.T) {
	tests := []struct {
		name     string
		output   string
		expected string
	}{
		{
			name:     "IOS XE detection",
			output:   "Cisco IOS XE Software, Version 16.9.1",
			expected: "IOS XE",
		},
		{
			name:     "NX-OS detection with Nexus",
			output:   "Cisco Nexus Operating System (NX-OS) Software",
			expected: "NX-OS",
		},
		{
			name:     "NX-OS detection with NX-OS",
			output:   "Cisco NX-OS(tm) Software, Version 9.3(5)",
			expected: "NX-OS",
		},
		{
			name: "NX-OS detection from live NXOS fields",
			output: `Software
  NXOS: version 10.4(5) [Maintenance Release]
  Host NXOS: version 10.4(5)

Hardware
  cisco Nexus9000 C9316D-GX Chassis`,
			expected: "NX-OS",
		},
		{
			name:     "IOS detection",
			output:   "Cisco IOS Software, C2960 Software",
			expected: "IOS",
		},
		{
			name:     "Unknown defaults to IOS XE",
			output:   "Some other output",
			expected: "IOS XE",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detectOSTypeFromShowVersion(tt.output)
			if result == "" {
				result = "IOS XE"
			}
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestOutputNeedsInteractiveShell(t *testing.T) {
	assert.True(t, outputNeedsInteractiveShell(`Line has invalid autocommand "show platform hardware qfp active datapath utilization"`))
	assert.False(t, outputNeedsInteractiveShell("Cisco IOS XE Software, Version 17.09.02a"))
}

func TestParseDeviceMetadataFromShowVersionIOSXE(t *testing.T) {
	now := time.Unix(100, 0)
	output := `Cisco IOS XE Software, Version 17.09.04a
Cisco IOS Software [Cupertino], Catalyst L3 Switch Software (CAT9K_IOSXE), Version 17.9.4a
cisco C9300-48P (X86) processor with 1417496K/6147K bytes of memory.
Processor board ID FCW1234L0AB
Switch uptime is 2 weeks, 3 days, 4 hours, 5 minutes`

	metadata := parseDeviceMetadataFromShowVersion(output, now)

	assert.Equal(t, "IOS XE", metadata.OSType)
	assert.Equal(t, "17.09.04a", metadata.OSVersion)
	assert.Equal(t, "Switch", metadata.HostName)
	assert.Equal(t, "C9300-48P", metadata.Model)
	assert.Equal(t, "FCW1234L0AB", metadata.Serial)
	assert.Equal(t, metadata.Serial, metadata.HostID)
	assert.Equal(t, metadata.Model, metadata.HostType)
	assert.Equal(t, int64((17*24*time.Hour + 4*time.Hour + 5*time.Minute).Seconds()), metadata.UptimeSeconds(now))
	assert.Equal(t, int64((17*24*time.Hour + 4*time.Hour + 6*time.Minute).Seconds()), metadata.UptimeSeconds(now.Add(time.Minute)))
}

func TestParseDeviceMetadataFromShowVersionNXOS(t *testing.T) {
	output := `Cisco Nexus Operating System (NX-OS) Software
Software
  NXOS: version 10.4(5) [Maintenance Release]
  Device name: leaf-01
Hardware
  cisco Nexus9000 C9316D-GX Chassis
  System serial number: FDO12345678
  Kernel uptime is 104 day(s), 6 hour(s), 10 minute(s), 20 second(s)`

	metadata := parseDeviceMetadataFromShowVersion(output, time.Unix(0, 0))

	assert.Equal(t, "NX-OS", metadata.OSType)
	assert.Equal(t, "10.4(5)", metadata.OSVersion)
	assert.Equal(t, "leaf-01", metadata.HostName)
	assert.Equal(t, "Nexus9000 C9316D-GX", metadata.Model)
	assert.Equal(t, "FDO12345678", metadata.Serial)
	assert.Equal(t, int64((104*24*time.Hour + 6*time.Hour + 10*time.Minute + 20*time.Second).Seconds()), metadata.UptimeSeconds(time.Unix(0, 0)))
}
