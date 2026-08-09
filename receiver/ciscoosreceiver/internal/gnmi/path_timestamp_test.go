// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package gnmi

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParsePathKeepsOriginSeparateAndRoundTrips(t *testing.T) {
	path, err := ParsePath("switch-1", "DME", `sys/intf/phys-[id="Ethernet1/1"][role=leaf]/sensor`)
	require.NoError(t, err)
	assert.Equal(t, "DME", path.Origin)
	assert.Equal(t, "phys-", path.Elements[2].Name)
	assert.Equal(t, "Ethernet1/1", path.Elements[2].Keys["id"])
	assert.Equal(t, `sys/intf/phys-[id="Ethernet1/1"][role=leaf]/sensor`, path.String())

	roundTrip := PathFromProto(path.ToProto())
	assert.Equal(t, path, roundTrip)

	rfc7951, err := ParsePath("wlc-1", "rfc7951", "Cisco-IOS-XE-platform-oper:components/component/state")
	require.NoError(t, err)
	assert.Equal(t, "rfc7951", rfc7951.Origin)
	assert.Equal(t, "Cisco-IOS-XE-platform-oper:components", rfc7951.Elements[0].Name)
}

func TestJoinPathsRejectsTargetAndOriginConflicts(t *testing.T) {
	prefix, err := ParsePath("xr-1", "Cisco-IOS-XR-optics", "ports")
	require.NoError(t, err)
	relative, err := ParsePath("xr-2", "Cisco-IOS-XR-otu", "port/state")
	require.NoError(t, err)
	_, err = JoinPaths(prefix, relative)
	require.ErrorContains(t, err, "conflicting path targets")

	relative.Target = "xr-1"
	_, err = JoinPaths(prefix, relative)
	require.ErrorContains(t, err, "conflicting path origins")
}

func TestPathHasPrefixAllowsUnkeyedBranchSelectors(t *testing.T) {
	path, err := ParsePath("nexus-1", "DME", "sys/intf/phys-[id=eth1]/lane[id=2]/sensor")
	require.NoError(t, err)
	allInterfaces, err := ParsePath("nexus-1", "DME", "sys/intf/phys-")
	require.NoError(t, err)
	otherInterface, err := ParsePath("nexus-1", "DME", "sys/intf/phys-[id=eth2]")
	require.NoError(t, err)
	assert.True(t, path.HasPrefix(allInterfaces))
	assert.False(t, path.HasPrefix(otherInterface))
}

func TestNormalizeTimestampMagnitudesAndBounds(t *testing.T) {
	want := time.Date(2026, time.July, 2, 12, 34, 56, 123_456_789, time.UTC)
	receipt := want.Add(time.Hour)
	tests := map[string]int64{
		"seconds":      want.Unix(),
		"milliseconds": want.UnixMilli(),
		"microseconds": want.UnixMicro(),
		"nanoseconds":  want.UnixNano(),
	}
	for name, raw := range tests {
		t.Run(name, func(t *testing.T) {
			got, valid := NormalizeTimestamp(raw, receipt)
			require.True(t, valid)
			switch name {
			case "seconds":
				assert.Equal(t, want.Truncate(time.Second), got)
			case "milliseconds":
				assert.Equal(t, want.Truncate(time.Millisecond), got)
			case "microseconds":
				assert.Equal(t, want.Truncate(time.Microsecond), got)
			default:
				assert.Equal(t, want, got)
			}
		})
	}

	for _, raw := range []int64{0, time.Date(1999, 1, 1, 0, 0, 0, 0, time.UTC).Unix(), receipt.Add(25 * time.Hour).UnixNano()} {
		got, valid := NormalizeTimestamp(raw, receipt)
		assert.False(t, valid)
		assert.Equal(t, receipt, got)
	}
}
