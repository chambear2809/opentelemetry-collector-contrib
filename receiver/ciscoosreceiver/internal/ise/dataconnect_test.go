// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ise

import (
	"context"
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
	assert.Contains(t, connector.query, "SELECT * FROM THREAT_EVENTS WHERE LOGGED_AT >= :1 ORDER BY LOGGED_AT DESC FETCH FIRST 3 ROWS ONLY")
	require.Len(t, connector.args, 1)
	_, ok := connector.args[0].Value.(time.Time)
	assert.True(t, ok)
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
