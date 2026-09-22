// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package kvmreceiver // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/kvmreceiver"

import (
	"context"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"time"

	"github.com/digitalocean/go-libvirt"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/receiver"
	"go.opentelemetry.io/collector/scraper/scrapererror"
	"go.uber.org/multierr"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/kvmreceiver/internal/metadata"
)

type kvmScraper struct {
	cfg    *Config
	client libvirtClient
	mb     *metadata.MetricsBuilder
}

func newScraper(cfg *Config, settings receiver.Settings) *kvmScraper {
	return &kvmScraper{
		cfg: cfg,
		mb:  metadata.NewMetricsBuilder(cfg.MetricsBuilderConfig, settings),
	}
}

func (*kvmScraper) start(_ context.Context, _ component.Host) error {
	// Connect lazily from scrape so a receiver can start before libvirtd is
	// available. The next collection attempt will retry the connection.
	return nil
}

func (s *kvmScraper) shutdown(_ context.Context) error {
	if s.client == nil {
		return nil
	}
	return s.client.Disconnect()
}

func (s *kvmScraper) scrape(ctx context.Context) (pmetric.Metrics, error) {
	if s.client == nil {
		client, err := newLibvirtClient(s.cfg.Endpoint)
		if err != nil {
			return pmetric.NewMetrics(), fmt.Errorf("connect to libvirt: %w", err)
		}
		s.client = client
	}

	if s.client == nil {
		return pmetric.NewMetrics(), errors.New("libvirt client is not connected")
	}

	domains, _, err := s.client.ConnectListAllDomains(1, libvirt.ConnectListDomainsActive|libvirt.ConnectListDomainsInactive)
	if err != nil {
		_ = s.client.Disconnect()
		s.client = nil
		return pmetric.NewMetrics(), fmt.Errorf("list libvirt domains: %w", err)
	}

	now := pcommon.NewTimestampFromTime(time.Now())
	var scrapeErrors scrapererror.ScrapeErrors
	for _, domain := range domains {
		if err := ctx.Err(); err != nil {
			return s.mb.Emit(), err
		}

		if err := s.scrapeDomain(domain, now); err != nil {
			scrapeErrors.AddPartial(1, fmt.Errorf("domain %q: %w", domain.Name, err))
		}
	}

	return s.mb.Emit(), scrapeErrors.Combine()
}

type domainDefinition struct {
	Devices struct {
		Disks      []domainDisk      `xml:"disk"`
		Interfaces []domainInterface `xml:"interface"`
	} `xml:"devices"`
}

type domainDisk struct {
	Device string `xml:"device,attr"`
	Target struct {
		Device string `xml:"dev,attr"`
	} `xml:"target"`
}

type domainInterface struct {
	Target struct {
		Device string `xml:"dev,attr"`
	} `xml:"target"`
}

func (s *kvmScraper) scrapeDomain(domain libvirt.Domain, now pcommon.Timestamp) error {
	state, maxMemoryKiB, currentMemoryKiB, virtualCPUs, cpuTime, err := s.client.DomainGetInfo(domain)
	if err != nil {
		return fmt.Errorf("get domain info: %w", err)
	}

	resourceBuilder := s.mb.NewResourceBuilder()
	resourceBuilder.SetKvmDomainName(domain.Name)
	resourceBuilder.SetKvmDomainUUID(formatUUID(domain.UUID))

	s.mb.RecordKvmDomainCPUCountDataPoint(now, int64(virtualCPUs))
	s.mb.RecordKvmDomainCPUTimeDataPoint(now, int64(cpuTime))
	s.mb.RecordKvmDomainMemoryMaximumDataPoint(now, int64(maxMemoryKiB)*1024)
	s.mb.RecordKvmDomainMemoryCurrentDataPoint(now, int64(currentMemoryKiB)*1024)
	s.mb.RecordKvmDomainStateDataPoint(now, 1, domainState(state))

	// Runtime block and interface statistics are unavailable for inactive
	// domains. Their libvirt domain ID is -1.
	if domain.ID < 0 {
		s.mb.EmitForResource(metadata.WithResource(resourceBuilder.Emit()))
		return nil
	}

	definition, err := s.domainDefinition(domain)
	if err != nil {
		s.mb.EmitForResource(metadata.WithResource(resourceBuilder.Emit()))
		return err
	}

	var scrapeErrors error
	for _, disk := range uniqueDisks(definition.Devices.Disks) {
		if err := s.scrapeDisk(domain, disk, now); err != nil {
			scrapeErrors = multierr.Append(scrapeErrors, err)
		}
	}
	for _, networkInterface := range uniqueInterfaces(definition.Devices.Interfaces) {
		if err := s.scrapeInterface(domain, networkInterface, now); err != nil {
			scrapeErrors = multierr.Append(scrapeErrors, err)
		}
	}

	s.mb.EmitForResource(metadata.WithResource(resourceBuilder.Emit()))
	return scrapeErrors
}

func (s *kvmScraper) domainDefinition(domain libvirt.Domain) (domainDefinition, error) {
	xmlDescription, err := s.client.DomainGetXMLDesc(domain, 0)
	if err != nil {
		return domainDefinition{}, fmt.Errorf("get domain XML: %w", err)
	}

	var definition domainDefinition
	if err := xml.Unmarshal([]byte(xmlDescription), &definition); err != nil {
		return domainDefinition{}, fmt.Errorf("parse domain XML: %w", err)
	}
	return definition, nil
}

func (s *kvmScraper) scrapeDisk(domain libvirt.Domain, disk domainDisk, now pcommon.Timestamp) error {
	readOperations, readBytes, writeOperations, writeBytes, errorsCount, err := s.client.DomainBlockStats(domain, disk.Target.Device)
	if err != nil {
		return fmt.Errorf("get disk stats for %q: %w", disk.Target.Device, err)
	}

	device := disk.Target.Device
	if readBytes >= 0 {
		s.mb.RecordKvmDomainDiskReadBytesDataPoint(now, readBytes, device)
	}
	if readOperations >= 0 {
		s.mb.RecordKvmDomainDiskReadOperationsDataPoint(now, readOperations, device)
	}
	if writeBytes >= 0 {
		s.mb.RecordKvmDomainDiskWriteBytesDataPoint(now, writeBytes, device)
	}
	if writeOperations >= 0 {
		s.mb.RecordKvmDomainDiskWriteOperationsDataPoint(now, writeOperations, device)
	}
	if errorsCount >= 0 {
		s.mb.RecordKvmDomainDiskErrorsDataPoint(now, errorsCount, device)
	}
	return nil
}

func (s *kvmScraper) scrapeInterface(domain libvirt.Domain, networkInterface domainInterface, now pcommon.Timestamp) error {
	rxBytes, rxPackets, rxErrors, rxDrops, txBytes, txPackets, txErrors, txDrops, err := s.client.DomainInterfaceStats(domain, networkInterface.Target.Device)
	if err != nil {
		return fmt.Errorf("get network stats for %q: %w", networkInterface.Target.Device, err)
	}

	device := networkInterface.Target.Device
	if rxBytes >= 0 {
		s.mb.RecordKvmDomainNetworkReceiveBytesDataPoint(now, rxBytes, device)
	}
	if rxPackets >= 0 {
		s.mb.RecordKvmDomainNetworkReceivePacketsDataPoint(now, rxPackets, device)
	}
	if rxErrors >= 0 {
		s.mb.RecordKvmDomainNetworkReceiveErrorsDataPoint(now, rxErrors, device)
	}
	if rxDrops >= 0 {
		s.mb.RecordKvmDomainNetworkReceiveDropsDataPoint(now, rxDrops, device)
	}
	if txBytes >= 0 {
		s.mb.RecordKvmDomainNetworkTransmitBytesDataPoint(now, txBytes, device)
	}
	if txPackets >= 0 {
		s.mb.RecordKvmDomainNetworkTransmitPacketsDataPoint(now, txPackets, device)
	}
	if txErrors >= 0 {
		s.mb.RecordKvmDomainNetworkTransmitErrorsDataPoint(now, txErrors, device)
	}
	if txDrops >= 0 {
		s.mb.RecordKvmDomainNetworkTransmitDropsDataPoint(now, txDrops, device)
	}
	return nil
}

func uniqueDisks(disks []domainDisk) []domainDisk {
	seen := make(map[string]struct{}, len(disks))
	result := make([]domainDisk, 0, len(disks))
	for _, disk := range disks {
		if disk.Target.Device == "" {
			continue
		}
		if _, ok := seen[disk.Target.Device]; ok {
			continue
		}
		seen[disk.Target.Device] = struct{}{}
		result = append(result, disk)
	}
	return result
}

func uniqueInterfaces(interfaces []domainInterface) []domainInterface {
	seen := make(map[string]struct{}, len(interfaces))
	result := make([]domainInterface, 0, len(interfaces))
	for _, networkInterface := range interfaces {
		if networkInterface.Target.Device == "" {
			continue
		}
		if _, ok := seen[networkInterface.Target.Device]; ok {
			continue
		}
		seen[networkInterface.Target.Device] = struct{}{}
		result = append(result, networkInterface)
	}
	return result
}

func formatUUID(id libvirt.UUID) string {
	encoded := hex.EncodeToString(id[:])
	if len(encoded) != 32 {
		return encoded
	}
	return encoded[:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:]
}

func domainState(state uint8) metadata.AttributeState {
	switch libvirt.DomainState(state) {
	case libvirt.DomainNostate:
		return metadata.AttributeStateNostate
	case libvirt.DomainRunning:
		return metadata.AttributeStateRunning
	case libvirt.DomainBlocked:
		return metadata.AttributeStateBlocked
	case libvirt.DomainPaused:
		return metadata.AttributeStatePaused
	case libvirt.DomainShutdown:
		return metadata.AttributeStateShutdown
	case libvirt.DomainShutoff:
		return metadata.AttributeStateShutoff
	case libvirt.DomainCrashed:
		return metadata.AttributeStateCrashed
	case libvirt.DomainPmsuspended:
		return metadata.AttributeStatePmsuspended
	default:
		return metadata.AttributeStateUnknown
	}
}
