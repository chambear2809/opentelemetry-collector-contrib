// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package kvmreceiver

import (
	"errors"
	"testing"

	"github.com/digitalocean/go-libvirt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/receiver/receivertest"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/kvmreceiver/internal/metadata"
)

type fakeLibvirtClient struct {
	domains        []libvirt.Domain
	info           map[string]domainInfo
	xml            map[string]string
	blockStats     map[string]blockStats
	interfaceStats map[string]interfaceStats
	blockCalls     int
	interfaceCalls int
	disconnected   bool
}

type domainInfo struct {
	state            uint8
	maxMemoryKiB     uint64
	currentMemoryKiB uint64
	virtualCPUs      uint16
	cpuTime          uint64
}

type blockStats struct {
	readOperations  int64
	readBytes       int64
	writeOperations int64
	writeBytes      int64
	errors          int64
}

type interfaceStats struct {
	receiveBytes    int64
	receivePackets  int64
	receiveErrors   int64
	receiveDrops    int64
	transmitBytes   int64
	transmitPackets int64
	transmitErrors  int64
	transmitDrops   int64
}

func (f *fakeLibvirtClient) ConnectListAllDomains(_ int32, _ libvirt.ConnectListAllDomainsFlags) ([]libvirt.Domain, uint32, error) {
	return f.domains, uint32(len(f.domains)), nil
}

func (f *fakeLibvirtClient) DomainGetInfo(domain libvirt.Domain) (uint8, uint64, uint64, uint16, uint64, error) {
	info, ok := f.info[domain.Name]
	if !ok {
		return 0, 0, 0, 0, 0, errors.New("domain info not found")
	}
	return info.state, info.maxMemoryKiB, info.currentMemoryKiB, info.virtualCPUs, info.cpuTime, nil
}

func (f *fakeLibvirtClient) DomainGetXMLDesc(domain libvirt.Domain, _ libvirt.DomainXMLFlags) (string, error) {
	xmlDescription, ok := f.xml[domain.Name]
	if !ok {
		return "", errors.New("domain XML not found")
	}
	return xmlDescription, nil
}

func (f *fakeLibvirtClient) DomainBlockStats(domain libvirt.Domain, device string) (int64, int64, int64, int64, int64, error) {
	f.blockCalls++
	stats, ok := f.blockStats[domain.Name+":"+device]
	if !ok {
		return 0, 0, 0, 0, 0, errors.New("block stats not found")
	}
	return stats.readOperations, stats.readBytes, stats.writeOperations, stats.writeBytes, stats.errors, nil
}

func (f *fakeLibvirtClient) DomainInterfaceStats(domain libvirt.Domain, device string) (int64, int64, int64, int64, int64, int64, int64, int64, error) {
	f.interfaceCalls++
	stats, ok := f.interfaceStats[domain.Name+":"+device]
	if !ok {
		return 0, 0, 0, 0, 0, 0, 0, 0, errors.New("interface stats not found")
	}
	return stats.receiveBytes, stats.receivePackets, stats.receiveErrors, stats.receiveDrops,
		stats.transmitBytes, stats.transmitPackets, stats.transmitErrors, stats.transmitDrops, nil
}

func (f *fakeLibvirtClient) Disconnect() error {
	f.disconnected = true
	return nil
}

func TestScrapeEmitsDomainAndDeviceMetrics(t *testing.T) {
	domain := libvirt.Domain{Name: "web", UUID: libvirt.UUID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}}
	fake := &fakeLibvirtClient{
		domains: []libvirt.Domain{domain},
		info: map[string]domainInfo{
			"web": {state: uint8(libvirt.DomainRunning), maxMemoryKiB: 2048, currentMemoryKiB: 1024, virtualCPUs: 2, cpuTime: 1234},
		},
		xml: map[string]string{
			"web": `<domain><devices><disk device="disk"><target dev="vda"/></disk><disk device="disk"><target dev="vda"/></disk><interface type="bridge"><target dev="vnet0"/></interface><interface type="bridge"><target dev="vnet0"/></interface></devices></domain>`,
		},
		blockStats: map[string]blockStats{
			"web:vda": {readOperations: 7, readBytes: 100, writeOperations: 8, writeBytes: 200, errors: 1},
		},
		interfaceStats: map[string]interfaceStats{
			"web:vnet0": {receiveBytes: 300, receivePackets: 30, receiveErrors: 3, receiveDrops: 4, transmitBytes: 400, transmitPackets: 40, transmitErrors: 5, transmitDrops: 6},
		},
	}

	cfg := newDefaultConfig().(*Config)
	scraper := newScraper(cfg, receivertest.NewNopSettings(metadata.Type))
	scraper.client = fake

	metrics, err := scraper.scrape(t.Context())
	require.NoError(t, err)
	require.Equal(t, 1, metrics.ResourceMetrics().Len())
	require.Equal(t, 1, fake.blockCalls)
	require.Equal(t, 1, fake.interfaceCalls)

	resource := metrics.ResourceMetrics().At(0).Resource().Attributes()
	name, ok := resource.Get("kvm.domain.name")
	require.True(t, ok)
	assert.Equal(t, "web", name.Str())
	uuid, ok := resource.Get("kvm.domain.uuid")
	require.True(t, ok)
	assert.Equal(t, "01020304-0506-0708-090a-0b0c0d0e0f10", uuid.Str())

	metricsByName := make(map[string]struct {
		value  int64
		device string
		state  string
	}, metrics.ResourceMetrics().At(0).ScopeMetrics().At(0).Metrics().Len())
	metricSlice := metrics.ResourceMetrics().At(0).ScopeMetrics().At(0).Metrics()
	for i := 0; i < metricSlice.Len(); i++ {
		metric := metricSlice.At(i)
		var dataPoints pmetric.NumberDataPointSlice
		switch metric.Type() {
		case pmetric.MetricTypeGauge:
			dataPoints = metric.Gauge().DataPoints()
		case pmetric.MetricTypeSum:
			dataPoints = metric.Sum().DataPoints()
		default:
			t.Fatalf("unexpected metric type %v for %s", metric.Type(), metric.Name())
		}
		require.Equal(t, 1, dataPoints.Len(), metric.Name())
		point := dataPoints.At(0)
		value := point.IntValue()
		device := ""
		state := ""
		if value, ok := point.Attributes().Get("device"); ok {
			device = value.Str()
		}
		if value, ok := point.Attributes().Get("state"); ok {
			state = value.Str()
		}
		metricsByName[metric.Name()] = struct {
			value  int64
			device string
			state  string
		}{value: value, device: device, state: state}
	}

	assert.Equal(t, int64(2), metricsByName["kvm.domain.cpu.count"].value)
	assert.Equal(t, int64(1234), metricsByName["kvm.domain.cpu.time"].value)
	assert.Equal(t, int64(2048*1024), metricsByName["kvm.domain.memory.maximum"].value)
	assert.Equal(t, int64(1024*1024), metricsByName["kvm.domain.memory.current"].value)
	assert.Equal(t, "running", metricsByName["kvm.domain.state"].state)
	assert.Equal(t, int64(100), metricsByName["kvm.domain.disk.read.bytes"].value)
	assert.Equal(t, int64(7), metricsByName["kvm.domain.disk.read.operations"].value)
	assert.Equal(t, int64(200), metricsByName["kvm.domain.disk.write.bytes"].value)
	assert.Equal(t, int64(8), metricsByName["kvm.domain.disk.write.operations"].value)
	assert.Equal(t, int64(1), metricsByName["kvm.domain.disk.errors"].value)
	assert.Equal(t, int64(300), metricsByName["kvm.domain.network.receive.bytes"].value)
	assert.Equal(t, int64(30), metricsByName["kvm.domain.network.receive.packets"].value)
	assert.Equal(t, int64(400), metricsByName["kvm.domain.network.transmit.bytes"].value)
	assert.Equal(t, int64(40), metricsByName["kvm.domain.network.transmit.packets"].value)
	assert.Equal(t, "vda", metricsByName["kvm.domain.disk.read.bytes"].device)
	assert.Equal(t, "vnet0", metricsByName["kvm.domain.network.receive.bytes"].device)
}

func TestScrapeReturnsPartialErrorForDeviceStats(t *testing.T) {
	domain := libvirt.Domain{Name: "web", ID: 1}
	fake := &fakeLibvirtClient{
		domains: []libvirt.Domain{domain},
		info:    map[string]domainInfo{"web": {state: uint8(libvirt.DomainShutoff), maxMemoryKiB: 1, currentMemoryKiB: 1, virtualCPUs: 1}},
		xml:     map[string]string{"web": `<domain><devices><disk device="disk"><target dev="vda"/></disk></devices></domain>`},
	}
	cfg := newDefaultConfig().(*Config)
	scraper := newScraper(cfg, receivertest.NewNopSettings(metadata.Type))
	scraper.client = fake

	metrics, err := scraper.scrape(t.Context())
	require.Error(t, err)
	require.NotEmpty(t, metrics.ResourceMetrics())
	assert.Contains(t, err.Error(), `get disk stats for "vda"`)
}

func TestScrapeSkipsRuntimeStatsForInactiveDomain(t *testing.T) {
	domain := libvirt.Domain{Name: "stopped", ID: -1}
	fake := &fakeLibvirtClient{
		domains: []libvirt.Domain{domain},
		info: map[string]domainInfo{
			"stopped": {state: uint8(libvirt.DomainShutoff), maxMemoryKiB: 2048, virtualCPUs: 2},
		},
	}

	cfg := newDefaultConfig().(*Config)
	scraper := newScraper(cfg, receivertest.NewNopSettings(metadata.Type))
	scraper.client = fake

	metrics, err := scraper.scrape(t.Context())
	require.NoError(t, err)
	require.Equal(t, 1, metrics.ResourceMetrics().Len())
	assert.Zero(t, fake.blockCalls)
	assert.Zero(t, fake.interfaceCalls)

	metricSlice := metrics.ResourceMetrics().At(0).ScopeMetrics().At(0).Metrics()
	names := make([]string, 0, metricSlice.Len())
	for i := 0; i < metricSlice.Len(); i++ {
		names = append(names, metricSlice.At(i).Name())
	}
	assert.ElementsMatch(t, []string{
		"kvm.domain.cpu.count",
		"kvm.domain.cpu.time",
		"kvm.domain.memory.current",
		"kvm.domain.memory.maximum",
		"kvm.domain.state",
	}, names)
}

func TestScrapeSkipsUnsupportedDeviceStats(t *testing.T) {
	domain := libvirt.Domain{Name: "web"}
	fake := &fakeLibvirtClient{
		domains: []libvirt.Domain{domain},
		info: map[string]domainInfo{
			"web": {state: uint8(libvirt.DomainRunning), maxMemoryKiB: 1, currentMemoryKiB: 1, virtualCPUs: 1},
		},
		xml: map[string]string{
			"web": `<domain><devices><disk device="disk"><target dev="vda"/></disk><interface><target dev="vnet0"/></interface></devices></domain>`,
		},
		blockStats: map[string]blockStats{
			"web:vda": {readOperations: 1, readBytes: 2, writeOperations: 3, writeBytes: 4, errors: -1},
		},
		interfaceStats: map[string]interfaceStats{
			"web:vnet0": {
				receiveBytes: 5, receivePackets: 6, receiveErrors: -1, receiveDrops: 7,
				transmitBytes: 8, transmitPackets: 9, transmitErrors: 10, transmitDrops: -1,
			},
		},
	}

	cfg := newDefaultConfig().(*Config)
	scraper := newScraper(cfg, receivertest.NewNopSettings(metadata.Type))
	scraper.client = fake

	metrics, err := scraper.scrape(t.Context())
	require.NoError(t, err)
	metricSlice := metrics.ResourceMetrics().At(0).ScopeMetrics().At(0).Metrics()
	names := make([]string, 0, metricSlice.Len())
	for i := 0; i < metricSlice.Len(); i++ {
		names = append(names, metricSlice.At(i).Name())
	}
	assert.NotContains(t, names, "kvm.domain.disk.errors")
	assert.NotContains(t, names, "kvm.domain.network.receive.errors")
	assert.NotContains(t, names, "kvm.domain.network.transmit.drops")
	assert.Contains(t, names, "kvm.domain.disk.read.bytes")
	assert.Contains(t, names, "kvm.domain.network.receive.bytes")
}
