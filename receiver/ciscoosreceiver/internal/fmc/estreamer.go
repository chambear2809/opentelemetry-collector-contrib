// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package fmc

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/httpclient"
)

const (
	estreamerDefaultPort                     = "8302"
	estreamerMessageHeaderLen                = 8
	estreamerMaxMessageBytes                 = 16 * 1024 * 1024
	estreamerMaxBundleRecords                = 100_000
	estreamerMessageNull              uint16 = 0
	estreamerMessageError             uint16 = 1
	estreamerMessageRequest           uint16 = 2
	estreamerMessageEventV3           uint16 = 3
	estreamerMessageEvent             uint16 = 4
	estreamerMessageBundle            uint16 = 4002
	estreamerRequestBitExtendedHeader        = uint32(1 << 23)
)

// EStreamerConfig controls an eStreamer fully-qualified-event client.
type EStreamerConfig struct {
	Address         string
	Name            string
	TLSConfig       *tls.Config
	InitialTime     time.Time
	EventTypes      []string
	DialTimeout     time.Duration
	ReadTimeout     time.Duration
	MaxMessageBytes int
}

// EStreamerStat describes eStreamer protocol activity.
type EStreamerStat struct {
	Controller string
	Outcome    string
	Message    string
	Events     int
	Bytes      int
	Err        error
}

// EStreamerEvent is a decoded eStreamer fully-qualified event.
type EStreamerEvent struct {
	Controller string
	EventType  string
	RecordType uint32
	Timestamp  time.Time
	Body       Object
	Raw        string
}

// EStreamerClient consumes Cisco eStreamer fully-qualified events.
type EStreamerClient struct {
	address         string
	name            string
	tlsConfig       *tls.Config
	initialTime     time.Time
	eventTypes      []string
	dialTimeout     time.Duration
	readTimeout     time.Duration
	maxMessageBytes int
	dialContext     func(context.Context, string, string) (net.Conn, error)

	OnStat func(EStreamerStat)
}

// NewEStreamerClient creates an eStreamer client.
func NewEStreamerClient(cfg EStreamerConfig) (*EStreamerClient, error) {
	if cfg.Address == "" {
		return nil, errors.New("fmc estreamer address is required")
	}
	address := cfg.Address
	if _, _, err := net.SplitHostPort(address); err != nil && !strings.Contains(address, ":") {
		address = net.JoinHostPort(address, estreamerDefaultPort)
	}
	name := cfg.Name
	if name == "" {
		name = address
	}
	dialTimeout := cfg.DialTimeout
	if dialTimeout <= 0 {
		dialTimeout = 30 * time.Second
	}
	readTimeout := cfg.ReadTimeout
	if readTimeout <= 0 {
		readTimeout = 5 * time.Minute
	}
	maxMessageBytes := cfg.MaxMessageBytes
	if maxMessageBytes < 0 || maxMessageBytes > estreamerMaxMessageBytes {
		return nil, fmt.Errorf("fmc estreamer max message bytes must be between 1 and %d when set", estreamerMaxMessageBytes)
	}
	if maxMessageBytes == 0 {
		maxMessageBytes = estreamerMaxMessageBytes
	}
	return &EStreamerClient{
		address:         address,
		name:            name,
		tlsConfig:       cfg.TLSConfig,
		initialTime:     cfg.InitialTime,
		eventTypes:      cfg.EventTypes,
		dialTimeout:     dialTimeout,
		readTimeout:     readTimeout,
		maxMessageBytes: maxMessageBytes,
	}, nil
}

// ControllerName returns a stable display name for the eStreamer endpoint.
func (c *EStreamerClient) ControllerName() string {
	return c.name
}

// Address returns the configured eStreamer endpoint address.
func (c *EStreamerClient) Address() string {
	return c.address
}

// InitialTime returns the configured startup cursor.
func (c *EStreamerClient) InitialTime() time.Time {
	return c.initialTime
}

// Run connects, requests fully-qualified events, and streams decoded events until ctx ends.
func (c *EStreamerClient) Run(ctx context.Context, onEvent func(EStreamerEvent) error) error {
	return c.RunFrom(ctx, c.initialTime, onEvent)
}

// RunFrom connects and requests fully-qualified events beginning at initialTime.
// Callers can advance initialTime between reconnects after downstream delivery
// succeeds. The eStreamer cursor has second-level resolution, so callers should
// retain a small overlap and suppress replayed boundary events.
func (c *EStreamerClient) RunFrom(ctx context.Context, initialTime time.Time, onEvent func(EStreamerEvent) error) error {
	dialContext := c.dialContext
	if dialContext == nil {
		dialer := &net.Dialer{Timeout: c.dialTimeout}
		tlsDialer := tls.Dialer{NetDialer: dialer, Config: c.tlsConfig}
		dialContext = tlsDialer.DialContext
	}
	conn, err := dialContext(ctx, "tcp", c.address)
	if err != nil {
		c.record(EStreamerStat{Controller: c.name, Outcome: "connect_error", Err: err})
		return err
	}
	defer conn.Close()
	// A socket read deadline based only on readTimeout does not react to receiver
	// shutdown. Moving the connection deadline to now when ctx is cancelled
	// promptly interrupts idle reads and writes without leaking a watcher goroutine.
	stopCancelDeadline := context.AfterFunc(ctx, func() {
		_ = conn.SetDeadline(time.Now())
	})
	defer stopCancelDeadline()
	c.record(EStreamerStat{Controller: c.name, Outcome: "connected"})

	if err := c.writeRequest(conn, initialTime); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		c.record(EStreamerStat{Controller: c.name, Outcome: "request_error", Err: err})
		return err
	}

	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		_ = conn.SetReadDeadline(time.Now().Add(c.readTimeout))
		header, payload, err := c.readMessage(conn)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			c.record(EStreamerStat{Controller: c.name, Outcome: "read_error", Err: err})
			return err
		}
		switch header.messageType {
		case estreamerMessageNull:
			c.record(EStreamerStat{Controller: c.name, Outcome: "keepalive"})
		case estreamerMessageError:
			err := decodeEStreamerError(payload)
			c.record(EStreamerStat{Controller: c.name, Outcome: "server_error", Err: err})
			return err
		case estreamerMessageBundle:
			events, err := decodeEStreamerBundle(c.name, payload)
			if err != nil {
				c.record(EStreamerStat{Controller: c.name, Outcome: "decode_error", Bytes: len(payload), Err: err})
				return err
			}
			if err := writeNullMessage(conn); err != nil {
				return err
			}
			c.record(EStreamerStat{Controller: c.name, Outcome: "events", Events: len(events), Bytes: len(payload)})
			for _, event := range events {
				if err := onEvent(event); err != nil {
					return err
				}
			}
		case estreamerMessageEventV3, estreamerMessageEvent:
			event := decodeEStreamerEvent(c.name, payload)
			c.record(EStreamerStat{Controller: c.name, Outcome: "events", Events: 1, Bytes: len(payload)})
			if err := onEvent(event); err != nil {
				return err
			}
		default:
			c.record(EStreamerStat{Controller: c.name, Outcome: "ignored", Message: fmt.Sprintf("message type %d", header.messageType), Bytes: len(payload)})
		}
	}
}

type estreamerHeader struct {
	version     uint16
	messageType uint16
	length      uint32
}

func (c *EStreamerClient) writeRequest(writer io.Writer, initialTime time.Time) error {
	request := defaultFQERequest(c.eventTypes)
	jsonBytes, err := json.Marshal(request)
	if err != nil {
		return err
	}
	initial := ^uint32(0)
	if !initialTime.IsZero() {
		initial = uint32(initialTime.Unix())
	}
	payload := make([]byte, 8+len(jsonBytes))
	binary.BigEndian.PutUint32(payload[0:4], initial)
	binary.BigEndian.PutUint32(payload[4:8], estreamerRequestBitExtendedHeader)
	copy(payload[8:], jsonBytes)
	message := encodeEStreamerMessage(estreamerMessageRequest, payload)
	return writeAll(writer, message)
}

func (c *EStreamerClient) readMessage(reader io.Reader) (estreamerHeader, []byte, error) {
	headerBytes := make([]byte, estreamerMessageHeaderLen)
	if _, err := io.ReadFull(reader, headerBytes); err != nil {
		return estreamerHeader{}, nil, err
	}
	header := decodeHeader(headerBytes)
	if header.version != 1 {
		return header, nil, fmt.Errorf("unexpected estreamer header version %d", header.version)
	}
	if uint64(header.length) > uint64(c.maxMessageBytes) {
		return header, nil, fmt.Errorf("estreamer message length %d exceeds max_message_bytes %d", header.length, c.maxMessageBytes)
	}
	payload := make([]byte, int(header.length))
	if len(payload) > 0 {
		if _, err := io.ReadFull(reader, payload); err != nil {
			return header, nil, err
		}
	}
	return header, payload, nil
}

func decodeEStreamerBundle(controller string, payload []byte) ([]EStreamerEvent, error) {
	if len(payload) < 8 {
		return nil, errors.New("estreamer bundle payload shorter than connection and sequence headers")
	}
	var events []EStreamerEvent
	recordCount := 0
	remaining := payload[8:]
	for len(remaining) > 0 {
		recordCount++
		if recordCount > estreamerMaxBundleRecords {
			return events, fmt.Errorf("estreamer bundle exceeds hard record/event limit of %d", estreamerMaxBundleRecords)
		}
		if len(remaining) < estreamerMessageHeaderLen {
			return events, fmt.Errorf("truncated estreamer bundled message header: %d bytes", len(remaining))
		}
		header := decodeHeader(remaining[:estreamerMessageHeaderLen])
		if header.version != 1 {
			return events, fmt.Errorf("unexpected estreamer bundled message version %d", header.version)
		}
		if uint64(header.length) > uint64(len(remaining)-estreamerMessageHeaderLen) {
			return events, fmt.Errorf("truncated estreamer bundled message: payload length %d exceeds %d remaining bytes", header.length, len(remaining)-estreamerMessageHeaderLen)
		}
		total := estreamerMessageHeaderLen + int(header.length)
		body := remaining[estreamerMessageHeaderLen:total]
		switch header.messageType {
		case estreamerMessageEventV3, estreamerMessageEvent:
			events = append(events, decodeEStreamerEvent(controller, body))
		case estreamerMessageNull:
		case estreamerMessageError:
			return events, decodeEStreamerError(body)
		}
		remaining = remaining[total:]
	}
	return events, nil
}

func decodeEStreamerEvent(controller string, payload []byte) EStreamerEvent {
	event := EStreamerEvent{Controller: controller}
	if len(payload) >= 8 {
		event.RecordType = binary.BigEndian.Uint32(payload[0:4])
		recordLength := int(binary.BigEndian.Uint32(payload[4:8]))
		if recordLength > 0 && 8+recordLength <= len(payload) {
			payload = payload[8 : 8+recordLength]
		} else {
			payload = payload[8:]
		}
	}
	trimmedPayload := bytes.TrimLeft(payload, "\x00\r\n\t ")
	if len(payload) >= 8 && len(trimmedPayload) > 0 && trimmedPayload[0] != '{' {
		if ts := binary.BigEndian.Uint32(payload[0:4]); ts > 0 {
			event.Timestamp = time.Unix(int64(ts), 0).UTC()
			payload = payload[8:]
		}
	}

	text := string(bytes.Trim(payload, "\x00\r\n\t "))
	event.Raw = text
	if text == "" {
		return event
	}
	start := strings.Index(text, "{")
	end := strings.LastIndex(text, "}")
	if start >= 0 && end >= start {
		text = text[start : end+1]
	}
	var decoded map[string]any
	if err := httpclient.DecodeJSON([]byte(text), &decoded); err != nil {
		fingerprint := sha256.Sum256([]byte(event.Raw))
		event.EventType = "decode_error"
		event.Body = Object{
			"decode_error":   true,
			"payload_sha256": fmt.Sprintf("%x", fingerprint),
		}
		event.Raw = ""
		return event
	}
	// Only the decoded JSON object is part of the event contract. Framing text
	// surrounding that object is device-controlled and can contain secrets.
	event.Raw = ""
	event.EventType = inferEStreamerEventType(decoded)
	event.Body = Object(decoded)
	if len(decoded) == 1 {
		for key, value := range decoded {
			if nested, ok := value.(map[string]any); ok {
				event.EventType = normalizeEStreamerEventType(key)
				event.Body = Object(nested)
			}
		}
	}
	if event.Timestamp.IsZero() {
		if ts, ok := Time(event.Body, "eventTime", "EventTime", "timestamp", "Time", "event_sec"); ok {
			event.Timestamp = ts
		}
	}
	return event
}

func decodeEStreamerError(payload []byte) error {
	fingerprint := sha256.Sum256(payload)
	if len(payload) < 4 {
		return fmt.Errorf("estreamer server error code=unavailable payload_length=%d payload_sha256=%x", len(payload), fingerprint)
	}
	code := int32(binary.BigEndian.Uint32(payload[0:4]))
	return fmt.Errorf("estreamer server error code=%d payload_length=%d payload_sha256=%x", code, len(payload), fingerprint)
}

func writeNullMessage(writer io.Writer) error {
	return writeAll(writer, encodeEStreamerMessage(estreamerMessageNull, nil))
}

func writeAll(writer io.Writer, payload []byte) error {
	for len(payload) > 0 {
		n, err := writer.Write(payload)
		if n < 0 || n > len(payload) {
			return io.ErrShortWrite
		}
		payload = payload[n:]
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

func encodeEStreamerMessage(messageType uint16, payload []byte) []byte {
	out := make([]byte, estreamerMessageHeaderLen+len(payload))
	binary.BigEndian.PutUint16(out[0:2], 1)
	binary.BigEndian.PutUint16(out[2:4], messageType)
	binary.BigEndian.PutUint32(out[4:8], uint32(len(payload)))
	copy(out[8:], payload)
	return out
}

func decodeHeader(payload []byte) estreamerHeader {
	return estreamerHeader{
		version:     binary.BigEndian.Uint16(payload[0:2]),
		messageType: binary.BigEndian.Uint16(payload[2:4]),
		length:      binary.BigEndian.Uint32(payload[4:8]),
	}
}

func inferEStreamerEventType(decoded map[string]any) string {
	for _, key := range []string{"EventType", "eventType", "event_type", "type", "Type"} {
		if value, ok := decoded[key].(string); ok && value != "" {
			return normalizeEStreamerEventType(value)
		}
	}
	for _, name := range []string{"ConnectionEvent", "IntrusionEvent", "IntrusionPacket", "FileEvent"} {
		if _, ok := decoded[name]; ok {
			return normalizeEStreamerEventType(name)
		}
	}
	return "unknown"
}

func normalizeEStreamerEventType(value string) string {
	value = strings.TrimSpace(value)
	replacer := strings.NewReplacer(" ", "_", "-", "_")
	value = replacer.Replace(value)
	var out []rune
	for i, char := range value {
		if i > 0 && char >= 'A' && char <= 'Z' {
			out = append(out, '_')
		}
		out = append(out, char)
	}
	return strings.ToLower(strings.Trim(string(out), "_"))
}

func defaultFQERequest(eventTypes []string) map[string]any {
	events := map[string]any{}
	for _, eventType := range normalizeFQEEventTypes(eventTypes) {
		switch eventType {
		case "connection":
			events["ConnectionEvent"] = fqeEventConfig([]string{"HeaderFieldSet", "ConnectionKeySet", "DetailFieldSet"})
		case "intrusion":
			events["IntrusionEvent"] = fqeEventConfig([]string{"HeaderFieldSet", "ConnectionKeySet", "DetailFieldSet", "Impact"})
		case "intrusion_packet":
			events["IntrusionPacket"] = fqeEventConfig([]string{"HeaderFieldSet", "DetailFieldSet"})
		case "file":
			events["FileEvent"] = fqeEventConfig([]string{"HeaderFieldSet", "ConnectionKeySet", "DetailFieldSet"})
		}
	}
	return map[string]any{
		"Events": events,
		"OutputFormat": map[string]string{
			"Transform":       "Text",
			"TransformConfig": "JSON",
		},
	}
}

func normalizeFQEEventTypes(values []string) []string {
	if len(values) == 0 {
		return []string{"connection", "intrusion", "intrusion_packet", "file"}
	}
	out := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		normalized := normalizeEStreamerEventType(value)
		switch normalized {
		case "connection_event", "traffic", "security_intelligence", "si":
			normalized = "connection"
		case "intrusion_event":
			normalized = "intrusion"
		case "intrusion_packet_event":
			normalized = "intrusion_packet"
		case "file_event", "malware", "file_malware":
			normalized = "file"
		}
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		out = append(out, normalized)
	}
	return out
}

func fqeEventConfig(fieldSets []string) map[string]any {
	return map[string]any{
		"FieldSetDef": map[string]any{
			"OutputFieldSet": fieldSets,
		},
		"Fields": []string{"OutputFieldSet"},
	}
}

func (c *EStreamerClient) record(stat EStreamerStat) {
	if c.OnStat != nil {
		c.OnStat(stat)
	}
}
