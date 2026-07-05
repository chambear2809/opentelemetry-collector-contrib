// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ise

import (
	"context"
	"crypto/x509"
	"database/sql"
	"database/sql/driver"
	"io"
	"strings"
	"testing"
	"time"

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

func TestDataConnectPingPromptsForExplicitSelfSignedLabOptIn(t *testing.T) {
	cause := x509.UnknownAuthorityError{Cert: &x509.Certificate{}}
	verified := &DataConnectClient{
		db:        sql.OpenDB(pingErrorConnector{err: cause}),
		sslVerify: true,
	}
	t.Cleanup(func() { require.NoError(t, verified.Close()) })

	err := verified.Ping(t.Context())
	require.ErrorIs(t, err, cause)
	assert.ErrorContains(t, err, "configure ise.data_connect.wallet_dir with the issuing CA (preferred)")
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
	assert.ErrorContains(t, err, "configure ise.data_connect.wallet_dir with the issuing CA (preferred)")
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
