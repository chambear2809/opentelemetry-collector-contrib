// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package yanggrpcreceiver

import (
	"context"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

func TestStreamAdmissionRejectsGlobalExcess(t *testing.T) {
	admission := newStreamAdmission(2, 2)
	_, releaseOne, err := admission.admit(streamAdmissionPeerContext("192.0.2.1", 1001))
	require.NoError(t, err)
	defer releaseOne()
	_, releaseTwo, err := admission.admit(streamAdmissionPeerContext("192.0.2.2", 1002))
	require.NoError(t, err)
	defer releaseTwo()

	_, _, err = admission.admit(streamAdmissionPeerContext("192.0.2.3", 1003))
	require.Equal(t, codes.ResourceExhausted, status.Code(err))
	assert.ErrorContains(t, err, "maximum active telemetry streams reached")
	assert.Equal(t, 2, admission.activeCount())

	releaseOne()
	_, releaseThree, err := admission.admit(streamAdmissionPeerContext("192.0.2.3", 1003))
	require.NoError(t, err)
	releaseThree()
}

func TestStreamAdmissionRejectsPerPeerExcessAcrossConnections(t *testing.T) {
	admission := newStreamAdmission(3, 1)
	_, releaseOne, err := admission.admit(streamAdmissionPeerContext("192.0.2.10", 1001))
	require.NoError(t, err)
	defer releaseOne()

	_, _, err = admission.admit(streamAdmissionPeerContext("192.0.2.10", 2002))
	require.Equal(t, codes.ResourceExhausted, status.Code(err))
	assert.ErrorContains(t, err, "maximum active telemetry streams for client reached")

	_, releaseOtherPeer, err := admission.admit(streamAdmissionPeerContext("192.0.2.11", 1001))
	require.NoError(t, err)
	releaseOtherPeer()
}

func TestStreamAdmissionShutdownCancelsAndRejects(t *testing.T) {
	admission := newStreamAdmission(2, 2)
	ctx, release, err := admission.admit(streamAdmissionPeerContext("2001:db8::10", 1001))
	require.NoError(t, err)
	defer release()

	admission.beginShutdown()
	require.ErrorIs(t, ctx.Err(), context.Canceled)
	_, _, err = admission.admit(streamAdmissionPeerContext("2001:db8::11", 1002))
	require.Equal(t, codes.Unavailable, status.Code(err))
	assert.ErrorContains(t, err, "telemetry receiver is shutting down")
}

func streamAdmissionPeerContext(ip string, port int) context.Context {
	return peer.NewContext(context.Background(), &peer.Peer{
		Addr: &net.TCPAddr{IP: net.ParseIP(ip), Port: port},
	})
}
