// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ise

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"database/sql/driver"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sijms/go-ora/v2/configurations"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDataConnectQueryViewUsesAllowlistedLookbackAndRowCap(t *testing.T) {
	connector := &captureConnector{}
	client := &DataConnectClient{db: sql.OpenDB(connector), rowLimit: 10, lookback: time.Hour}
	defer client.Close()

	rows, err := client.QueryView(t.Context(), DataConnectView{Name: "THREAT_EVENTS", Category: "security", TimeColumn: "LOGGED_AT", MaxResults: 3})
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Equal(t, "1", rows[0]["ID"])
	assert.Equal(t, time.Unix(100, 0).UTC().Format(time.RFC3339Nano), rows[0]["LOGGED_AT"])
	assert.Contains(t, connector.query, "SELECT * FROM THREAT_EVENTS WHERE LOGGED_AT >= :1 ORDER BY LOGGED_AT DESC FETCH FIRST 3 ROWS ONLY")
	require.Len(t, connector.args, 1)
	_, ok := connector.args[0].Value.(time.Time)
	assert.True(t, ok)
}

func TestNewDataConnectClientRejectsPlaintextCredentials(t *testing.T) {
	client, err := NewDataConnectClient(DataConnectConfig{
		Host:        "ise.example.test",
		ServiceName: "cpm10",
		Username:    "dataconnect",
		Password:    "secret",
	})
	require.Error(t, err)
	assert.Nil(t, client)
	assert.ErrorContains(t, err, "SSL must be enabled")
}

func TestNewDataConnectClientConfiguresPEMTrustAndServerName(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(server.Close)
	serverHost, serverPort, err := net.SplitHostPort(server.Listener.Addr().String())
	require.NoError(t, err)
	caFile := writeDataConnectTestCA(t, server.Certificate())

	connector := &configuredDataConnectConnector{}
	var dsn string
	client, err := newDataConnectClient(DataConnectConfig{
		Host:        serverHost,
		Port:        mustDataConnectTestPort(t, serverPort),
		ServiceName: "cpm10",
		Username:    "dataconnect",
		Password:    "secret",
		CAFile:      caFile,
		ServerName:  "example.com",
		SSL:         true,
		SSLVerify:   true,
	}, func(value string) (dataConnectOracleConnector, error) {
		dsn = value
		return connector, nil
	})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, client.Close()) })

	parsed, err := url.Parse(dsn)
	require.NoError(t, err)
	assert.Equal(t, "example.com", parsed.Hostname())
	require.NotNil(t, connector.tlsConfig)
	assert.Equal(t, "example.com", connector.tlsConfig.ServerName)
	assert.Equal(t, uint16(tls.VersionTLS12), connector.tlsConfig.MinVersion)
	require.NotNil(t, connector.tlsConfig.RootCAs)
	_, err = server.Certificate().Verify(x509.VerifyOptions{Roots: connector.tlsConfig.RootCAs})
	require.NoError(t, err)

	// The TLS config is usable against the private CA, independent of Oracle's
	// application protocol. This proves both chain and hostname verification.
	tlsConn, err := tls.Dial("tcp", server.Listener.Addr().String(), connector.tlsConfig.Clone())
	require.NoError(t, err)
	require.NoError(t, tlsConn.Close())

	dialer, ok := connector.dialer.(*dataConnectServerNameDialer)
	require.True(t, ok)
	dialedAddress := ""
	dialer.dialContext = func(_ context.Context, _, address string) (net.Conn, error) {
		dialedAddress = address
		return nil, assert.AnError
	}
	_, err = dialer.DialContext(t.Context(), "tcp", net.JoinHostPort("example.com", serverPort))
	require.ErrorIs(t, err, assert.AnError)
	assert.Equal(t, net.JoinHostPort(serverHost, serverPort), dialedAddress)

	_, err = dialer.DialContext(t.Context(), "tcp", net.JoinHostPort("redirect.example.com", serverPort))
	require.ErrorIs(t, err, assert.AnError)
	assert.Equal(t, net.JoinHostPort("redirect.example.com", serverPort), dialedAddress)
}

func TestNewDataConnectClientPreservesWalletTLSWithServerName(t *testing.T) {
	connector := &configuredDataConnectConnector{}
	var dsn string
	client, err := newDataConnectClient(DataConnectConfig{
		Host:        "192.0.2.10",
		Port:        2484,
		ServiceName: "cpm10",
		Username:    "dataconnect",
		Password:    "secret",
		WalletDir:   "/etc/otelcol/ise-wallet",
		ServerName:  "ise.example.com",
		SSL:         true,
		SSLVerify:   true,
	}, func(value string) (dataConnectOracleConnector, error) {
		dsn = value
		return connector, nil
	})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, client.Close()) })

	parsed, err := url.Parse(dsn)
	require.NoError(t, err)
	assert.Equal(t, "ise.example.com", parsed.Hostname())
	assert.Equal(t, "/etc/otelcol/ise-wallet", parsed.Query().Get("WALLET"))
	assert.Nil(t, connector.tlsConfig, "WithTLSConfig would replace go-ora wallet trust material")
	assert.IsType(t, &dataConnectServerNameDialer{}, connector.dialer)
	assert.Equal(t, dataConnectWalletConfigPath, client.trustConfigPath)
}

func TestNewDataConnectClientRejectsInvalidPEMTrustConfiguration(t *testing.T) {
	base := DataConnectConfig{
		Host:        "ise.example.com",
		Port:        2484,
		ServiceName: "cpm10",
		Username:    "dataconnect",
		Password:    "secret",
		SSL:         true,
		SSLVerify:   true,
	}

	t.Run("missing CA file", func(t *testing.T) {
		cfg := base
		cfg.CAFile = t.TempDir() + "/missing.pem"
		client, err := NewDataConnectClient(cfg)
		assert.Nil(t, client)
		require.Error(t, err)
		assert.ErrorContains(t, err, "read ise.data_connect.ca_file")
	})

	t.Run("invalid CA PEM", func(t *testing.T) {
		cfg := base
		cfg.CAFile = t.TempDir() + "/invalid.pem"
		require.NoError(t, os.WriteFile(cfg.CAFile, []byte("not a certificate"), 0o600))
		client, err := NewDataConnectClient(cfg)
		assert.Nil(t, client)
		require.Error(t, err)
		assert.ErrorContains(t, err, "ise.data_connect.ca_file")
		assert.ErrorContains(t, err, "did not contain PEM certificates")
	})

	t.Run("wallet and CA", func(t *testing.T) {
		cfg := base
		cfg.WalletDir = "/etc/otelcol/ise-wallet"
		cfg.CAFile = "/etc/otelcol/ise-ca.pem"
		client, err := NewDataConnectClient(cfg)
		assert.Nil(t, client)
		require.Error(t, err)
		assert.ErrorContains(t, err, "wallet_dir cannot be combined with ca_file")
	})

	t.Run("CA with verification disabled", func(t *testing.T) {
		cfg := base
		cfg.CAFile = "/etc/otelcol/ise-ca.pem"
		cfg.SSLVerify = false
		client, err := NewDataConnectClient(cfg)
		assert.Nil(t, client)
		require.Error(t, err)
		assert.ErrorContains(t, err, "ca_file requires ssl_verify to be true")
	})
}

func TestDataConnectPingPromptsForExplicitSelfSignedLabOptIn(t *testing.T) {
	cause := x509.UnknownAuthorityError{Cert: &x509.Certificate{}}
	verified := &DataConnectClient{
		db:        sql.OpenDB(pingErrorConnector{err: cause}),
		sslVerify: true,
	}
	t.Cleanup(func() { require.NoError(t, verified.Close()) })

	err := verified.Ping(t.Context())
	require.ErrorIs(t, err, cause)
	assert.ErrorContains(t, err, "configure ise.data_connect.ca_file with the issuing CA (preferred)")
	assert.ErrorContains(t, err, "set ise.data_connect.ssl_verify: false only for an isolated lab")

	lab := &DataConnectClient{
		db:        sql.OpenDB(pingErrorConnector{err: cause}),
		sslVerify: false,
	}
	t.Cleanup(func() { require.NoError(t, lab.Close()) })
	assert.ErrorIs(t, lab.Ping(t.Context()), cause)
}

func TestDataConnectQueryPromptsForExplicitSelfSignedLabOptIn(t *testing.T) {
	cause := x509.UnknownAuthorityError{Cert: &x509.Certificate{}}
	client := &DataConnectClient{
		db:        sql.OpenDB(pingErrorConnector{err: cause}),
		rowLimit:  10,
		sslVerify: true,
	}
	t.Cleanup(func() { require.NoError(t, client.Close()) })

	objects, err := client.QueryView(t.Context(), DataConnectView{Name: "NODE_LIST"})
	assert.Empty(t, objects)
	require.ErrorIs(t, err, cause)
	assert.ErrorContains(t, err, "configure ise.data_connect.ca_file with the issuing CA (preferred)")
	assert.ErrorContains(t, err, "set ise.data_connect.ssl_verify: false only for an isolated lab")
}

func TestDataConnectQueryViewRejectsExcessiveColumnCount(t *testing.T) {
	columns := make([]string, maxDataConnectResultColumns+1)
	for i := range columns {
		columns[i] = "COLUMN"
	}
	connector := &captureConnector{rows: &staticRows{columns: columns}}
	client := &DataConnectClient{db: sql.OpenDB(connector), rowLimit: 10}
	defer client.Close()

	objects, err := client.QueryView(t.Context(), DataConnectView{Name: "NODE_LIST"})
	require.Empty(t, objects)
	var limitErr *DataConnectResultLimitError
	require.ErrorAs(t, err, &limitErr)
	assert.Equal(t, "column count", limitErr.Kind)
	assert.Equal(t, maxDataConnectResultColumns, limitErr.Maximum)
	assert.Equal(t, maxDataConnectResultColumns+1, limitErr.Observed)
	assert.Zero(t, limitErr.Rows)
}

func TestScanRowsReturnsCompleteRowsBeforeAggregateByteLimit(t *testing.T) {
	connector := &captureConnector{rows: &staticRows{
		columns: []string{"ID", "PAYLOAD"},
		values: [][]driver.Value{
			{"one", []byte("normal")},
			{"two", []byte(strings.Repeat("x", 512))},
		},
	}}
	db := sql.OpenDB(connector)
	defer db.Close()
	dbRows, err := db.QueryContext(t.Context(), "SELECT * FROM NODE_LIST")
	require.NoError(t, err)
	defer dbRows.Close()

	objects, err := scanRowsWithBudget(dbRows, &dataConnectResultBudget{maximum: 400})
	require.Len(t, objects, 1)
	assert.Equal(t, "one", objects[0]["ID"])
	assert.Equal(t, "normal", objects[0]["PAYLOAD"])
	var limitErr *DataConnectResultLimitError
	require.ErrorAs(t, err, &limitErr)
	assert.Equal(t, "retained byte", limitErr.Kind)
	assert.Equal(t, 400, limitErr.Maximum)
	assert.Equal(t, 1, limitErr.Rows)
}

func TestDataConnectQueryViewRejectsUnsafeIdentifiersBeforeSQL(t *testing.T) {
	connector := &captureConnector{}
	client := &DataConnectClient{db: sql.OpenDB(connector), rowLimit: 10, lookback: time.Hour}
	defer client.Close()

	_, err := client.QueryView(t.Context(), DataConnectView{Name: "THREAT_EVENTS;DROP TABLE USERS"})
	require.Error(t, err)
	assert.Empty(t, connector.query)
}

type captureConnector struct {
	query string
	args  []driver.NamedValue
	rows  driver.Rows
}

type configuredDataConnectConnector struct {
	captureConnector
	tlsConfig *tls.Config
	dialer    configurations.DialerContext
}

func (c *configuredDataConnectConnector) WithTLSConfig(cfg *tls.Config) {
	c.tlsConfig = cfg
}

func (c *configuredDataConnectConnector) Dialer(dialer configurations.DialerContext) {
	c.dialer = dialer
}

func writeDataConnectTestCA(t *testing.T, cert *x509.Certificate) string {
	t.Helper()
	path := t.TempDir() + "/ise-ca.pem"
	encoded := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	require.NoError(t, os.WriteFile(path, encoded, 0o600))
	return path
}

func mustDataConnectTestPort(t *testing.T, value string) int {
	t.Helper()
	port, err := strconv.Atoi(value)
	require.NoError(t, err)
	return port
}

type pingErrorConnector struct {
	err error
}

func (c pingErrorConnector) Connect(context.Context) (driver.Conn, error) {
	return nil, c.err
}

func (pingErrorConnector) Driver() driver.Driver {
	return captureDriver{}
}

func (c *captureConnector) Connect(context.Context) (driver.Conn, error) {
	return &captureConn{connector: c}, nil
}

func (*captureConnector) Driver() driver.Driver {
	return captureDriver{}
}

type captureDriver struct{}

func (captureDriver) Open(string) (driver.Conn, error) {
	return &captureConn{}, nil
}

type captureConn struct {
	connector *captureConnector
}

func (*captureConn) Prepare(string) (driver.Stmt, error) {
	return nil, driver.ErrSkip
}

func (*captureConn) Close() error {
	return nil
}

func (*captureConn) Begin() (driver.Tx, error) {
	return nil, driver.ErrSkip
}

func (c *captureConn) QueryContext(_ context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	c.connector.query = strings.Join(strings.Fields(query), " ")
	c.connector.args = append([]driver.NamedValue(nil), args...)
	if c.connector.rows != nil {
		return c.connector.rows, nil
	}
	return &captureRows{}, nil
}

type captureRows struct {
	sent bool
}

func (*captureRows) Columns() []string {
	return []string{"ID", "LOGGED_AT"}
}

func (*captureRows) Close() error {
	return nil
}

func (r *captureRows) Next(dest []driver.Value) error {
	if r.sent {
		return io.EOF
	}
	r.sent = true
	dest[0] = "1"
	dest[1] = time.Unix(100, 0).UTC()
	return nil
}

type staticRows struct {
	columns []string
	values  [][]driver.Value
	index   int
}

func (r *staticRows) Columns() []string {
	return r.columns
}

func (*staticRows) Close() error {
	return nil
}

func (r *staticRows) Next(dest []driver.Value) error {
	if r.index >= len(r.values) {
		return io.EOF
	}
	copy(dest, r.values[r.index])
	r.index++
	return nil
}
