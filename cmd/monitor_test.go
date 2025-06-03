package cmd

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestTraceFileImapSieve(t *testing.T) {
	m := NewMonitor()
	m.Verbose = true
	file := TraceFile{Filename: "testdata/imapsieve.trace"}
	forward := file.shouldForward(m)
	require.False(t, forward)
}

func TestTraceFileDaemon(t *testing.T) {
	m := NewMonitor()
	m.Verbose = true
	file := TraceFile{Filename: "testdata/daemon.trace"}
	forward := file.shouldForward(m)
	require.False(t, forward)
}

func TestTraceFileDelivery(t *testing.T) {
	m := NewMonitor()
	m.Verbose = true
	file := TraceFile{Filename: "testdata/delivery.trace"}
	forward := file.shouldForward(m)
	require.True(t, forward)
}
