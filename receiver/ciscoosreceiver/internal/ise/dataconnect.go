// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ise

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	go_ora "github.com/sijms/go-ora/v2"
)

const defaultDataConnectRowLimit = 5000

var dataConnectViewNamePattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)

// DataConnectConfig controls Cisco ISE Data Connect database access.
type DataConnectConfig struct {
	Host               string
	Port               int
	ServiceName        string
	Username           string
	Password           string
	WalletDir          string
	SSL                bool
	SSLVerify          bool
	Lookback           time.Duration
	RowLimit           int
	FullViews          bool
	AdditionalReadOnly []string
}

// DataConnectView describes one allowlisted read-only Cisco ISE Data Connect view.
type DataConnectView struct {
	Name       string
	Category   string
	MaxResults int
	TimeColumn string
}

// DataConnectStat describes one Data Connect query.
type DataConnectStat struct {
	View     string
	Outcome  string
	Rows     int
	Duration time.Duration
	Err      error
}

// DataConnectClient is a read-only Cisco ISE Data Connect client.
type DataConnectClient struct {
	db       *sql.DB
	rowLimit int
	lookback time.Duration

	OnQuery func(DataConnectStat)
}

// NewDataConnectClient creates a Data Connect client.
func NewDataConnectClient(cfg DataConnectConfig) (*DataConnectClient, error) {
	if cfg.Host == "" || cfg.ServiceName == "" || cfg.Username == "" || cfg.Password == "" {
		return nil, errors.New("Data Connect host, service name, username, and password are required")
	}
	rowLimit := cfg.RowLimit
	if rowLimit <= 0 {
		rowLimit = defaultDataConnectRowLimit
	}
	options := map[string]string{}
	if cfg.SSL {
		options["SSL"] = "enable"
	}
	if !cfg.SSLVerify {
		options["SSL VERIFY"] = "false"
	}
	if cfg.WalletDir != "" {
		options["WALLET"] = cfg.WalletDir
	}
	dsn := go_ora.BuildUrl(cfg.Host, cfg.Port, cfg.ServiceName, cfg.Username, cfg.Password, options)
	db, err := sql.Open("oracle", dsn)
	if err != nil {
		return nil, err
	}
	return &DataConnectClient{db: db, rowLimit: rowLimit, lookback: cfg.Lookback}, nil
}

// Close closes the underlying database handle.
func (c *DataConnectClient) Close() error {
	if c == nil || c.db == nil {
		return nil
	}
	return c.db.Close()
}

// Ping verifies Data Connect connectivity.
func (c *DataConnectClient) Ping(ctx context.Context) error {
	return c.db.PingContext(ctx)
}

// QueryView returns rows from one allowlisted Data Connect view.
func (c *DataConnectClient) QueryView(ctx context.Context, view DataConnectView) ([]Object, error) {
	if !ValidDataConnectViewName(view.Name) || IsInternalDataConnectView(view.Name) {
		return nil, fmt.Errorf("Data Connect view %q is not allowlisted", view.Name)
	}
	limit := c.rowLimit
	if view.MaxResults > 0 && view.MaxResults < limit {
		limit = view.MaxResults
	}
	if limit <= 0 {
		limit = defaultDataConnectRowLimit
	}
	viewName := strings.ToUpper(view.Name)
	timeColumn := strings.ToUpper(strings.TrimSpace(view.TimeColumn))
	if timeColumn != "" && !ValidDataConnectViewName(timeColumn) {
		return nil, fmt.Errorf("Data Connect time column %q is not allowlisted", view.TimeColumn)
	}
	var (
		query string
		args  []any
	)
	if timeColumn != "" && c.lookback > 0 {
		query = fmt.Sprintf("SELECT * FROM %s WHERE %s >= :1 ORDER BY %s DESC FETCH FIRST %d ROWS ONLY", viewName, timeColumn, timeColumn, limit)
		args = append(args, time.Now().UTC().Add(-c.lookback))
	} else if timeColumn != "" {
		query = fmt.Sprintf("SELECT * FROM %s ORDER BY %s DESC FETCH FIRST %d ROWS ONLY", viewName, timeColumn, limit)
	} else {
		query = fmt.Sprintf("SELECT * FROM %s FETCH FIRST %d ROWS ONLY", viewName, limit)
	}
	start := time.Now()
	rows, err := c.db.QueryContext(ctx, query, args...)
	if err != nil {
		c.record(DataConnectStat{View: view.Name, Outcome: "error", Duration: time.Since(start), Err: err})
		return nil, err
	}
	defer rows.Close()
	objects, err := scanRows(rows)
	if err != nil {
		c.record(DataConnectStat{View: view.Name, Outcome: "error", Rows: len(objects), Duration: time.Since(start), Err: err})
		return objects, err
	}
	c.record(DataConnectStat{View: view.Name, Outcome: "success", Rows: len(objects), Duration: time.Since(start)})
	return objects, nil
}

func (c *DataConnectClient) record(stat DataConnectStat) {
	if c.OnQuery != nil {
		c.OnQuery(stat)
	}
}

func scanRows(rows *sql.Rows) ([]Object, error) {
	columns, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	var objects []Object
	for rows.Next() {
		values := make([]any, len(columns))
		pointers := make([]any, len(columns))
		for i := range values {
			pointers[i] = &values[i]
		}
		if err := rows.Scan(pointers...); err != nil {
			return objects, err
		}
		obj := Object{}
		for i, column := range columns {
			obj[column] = normalizeDBValue(values[i])
		}
		objects = append(objects, obj)
	}
	if err := rows.Err(); err != nil {
		return objects, err
	}
	return objects, nil
}

func normalizeDBValue(value any) any {
	switch typed := value.(type) {
	case []byte:
		return string(typed)
	case time.Time:
		return typed.UTC().Format(time.RFC3339Nano)
	default:
		return typed
	}
}

// ValidDataConnectViewName reports whether view is a safe SQL identifier.
func ValidDataConnectViewName(view string) bool {
	return dataConnectViewNamePattern.MatchString(strings.ToUpper(strings.TrimSpace(view)))
}

// IsInternalDataConnectView reports whether a view is documented as internal and should not be collected.
func IsInternalDataConnectView(view string) bool {
	switch strings.ToUpper(strings.TrimSpace(view)) {
	case "UPSPOLICY", "UPSPOLICYSET", "UPSPOLICYSET_POLICIES":
		return true
	default:
		return false
	}
}

// DefaultDataConnectViews returns the documented read-only ISE Data Connect view allowlist.
func DefaultDataConnectViews() []DataConnectView {
	return []DataConnectView{
		{Name: "NODE_LIST", Category: "core"},
		{Name: "NETWORK_DEVICES", Category: "core"},
		{Name: "NETWORK_DEVICE_GROUPS", Category: "core"},
		{Name: "POLICY_SETS", Category: "policy"},
		{Name: "OPENAPI_OPERATIONS", Category: "audit", TimeColumn: "LOGGED_AT"},
		{Name: "ADMINISTRATOR_LOGINS", Category: "audit", TimeColumn: "TIMESTAMP"},
		{Name: "ADMIN_USERS", Category: "audit"},
		{Name: "RADIUS_AUTHENTICATIONS_WEEK", Category: "radius", TimeColumn: "TIMESTAMP"},
		{Name: "RADIUS_ACCOUNTING_WEEK", Category: "radius", TimeColumn: "TIMESTAMP"},
		{Name: "TACACS_AUTHENTICATION_LAST_TWO_DAYS", Category: "tacacs", TimeColumn: "LOGGED_TIME"},
		{Name: "TACACS_AUTHORIZATION_LAST_TWO_DAYS", Category: "tacacs", TimeColumn: "LOGGED_TIME"},
		{Name: "TACACS_ACCOUNTING_LAST_TWO_DAYS", Category: "tacacs", TimeColumn: "LOGGED_TIME"},
		{Name: "TACACS_COMMAND_ACCOUNTING", Category: "tacacs", TimeColumn: "LOGGED_TIME"},
		{Name: "POSTURE_ASSESSMENT_BY_ENDPOINT", Category: "posture", TimeColumn: "TIMESTAMP"},
		{Name: "PROFILED_ENDPOINTS_SUMMARY", Category: "profiler", TimeColumn: "TIMESTAMP"},
		{Name: "PROFILING_POLICIES", Category: "profiler"},
		{Name: "ADAPTIVE_NETWORK_CONTROL", Category: "security", TimeColumn: "LOGGED_AT"},
		{Name: "THREAT_EVENTS", Category: "security", TimeColumn: "LOGGED_AT"},
		{Name: "USER_IDENTITY_GROUPS", Category: "identity"},
	}
}

// FullDataConnectViews returns larger historical views that are only queried when explicitly enabled.
func FullDataConnectViews() []DataConnectView {
	return []DataConnectView{
		{Name: "RADIUS_AUTHENTICATIONS", Category: "radius", TimeColumn: "TIMESTAMP"},
		{Name: "RADIUS_ACCOUNTING", Category: "radius", TimeColumn: "TIMESTAMP"},
		{Name: "TACACS_AUTHENTICATION", Category: "tacacs", TimeColumn: "LOGGED_TIME"},
		{Name: "TACACS_AUTHORIZATION", Category: "tacacs", TimeColumn: "LOGGED_TIME"},
		{Name: "TACACS_ACCOUNTING", Category: "tacacs", TimeColumn: "LOGGED_TIME"},
	}
}
